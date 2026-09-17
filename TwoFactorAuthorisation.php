<?php

defined( 'ABSPATH' ) or die( 'There`s nothing here!' );

class TwoFactorAuthorisation {

	public function __construct() {
	}

	public function add_actions() {
		add_action( 'login_form', [ $this, 'add_2fa_form' ] );
		add_filter( 'authenticate', [ $this, 'verify_totp_code' ], 100, 3 );

		add_action( 'show_user_profile', [ $this, 'display_qr_code' ], 1, 1 );
		add_action( 'edit_user_profile', [ $this, 'display_qr_code' ], 1, 1 );

		add_action( 'wp_ajax_generate_pending_secret', [ $this, 'handle_generate_pending_secret' ] );
		add_action( 'wp_ajax_confirm_totp_setup',      [ $this, 'handle_confirm_totp_setup' ] );
		add_action( 'wp_ajax_regenerate_secret',       [ $this, 'handle_secret_regeneration' ] );
		add_action( 'wp_ajax_delete_secret',           [ $this, 'handle_secret_delete' ] );

		add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_scripts' ], 99 );
	}

	// -------------------------------------------------------------------------
	// Login form: field for the TOTP code
	// -------------------------------------------------------------------------

	public function add_2fa_form() {
		echo '<p>
			<label for="totp_code">' .
		     __( 'Enter the 2FA code if you have one installed', 'login-sec' ) . ':
			</label>
			<input type="text" name="totp_code" id="totp_code" class="input" value="" size="20"
			       autocomplete="one-time-code" inputmode="numeric" />
		</p>';
	}

	// -------------------------------------------------------------------------
	// Authenticate filter: verify TOTP on login
	// Runs ONLY when 2FA is fully set up (totp_secret + totp_verified = 1)
	// -------------------------------------------------------------------------

	public function verify_totp_code( $user, $username, $password ) {
		$user_id = username_exists( $username );
		$user_id = ! empty( $user_id ) ? $user_id : email_exists( $username );

		if ( $user_id === false ) {
			return $user;
		}

		$secret   = get_user_meta( $user_id, 'totp_secret', true );
		$verified = get_user_meta( $user_id, 'totp_verified', true );

		// 2FA not set up or not confirmed yet — skip check
		if ( empty( $secret ) || ! $verified ) {
			return $user;
		}

		$code = trim( $_POST['totp_code'] ?? '' );

		// Allow +-1 time-step window to tolerate minor clock drift
		if ( ! $this->verify_code_with_window( $secret, $code ) ) {
			return new WP_Error( 'invalid_totp', __( 'Invalid 2FA code.', 'login-sec' ) );
		}

		return $user;
	}

	/**
	 * Verify TOTP code with +-1 step window (30 s each).
	 */
	private function verify_code_with_window( string $secret, string $code ): bool {
		if ( strlen( $code ) !== 6 || ! ctype_digit( $code ) ) {
			return false;
		}
		for ( $offset = - 1; $offset <= 1; $offset ++ ) {
			$time_slice = floor( time() / 30 ) + $offset;
			$candidate  = Auth2FA::TOTP_at( $secret, $time_slice );
			if ( hash_equals( $candidate, $code ) ) {
				return true;
			}
		}

		return false;
	}

	// -------------------------------------------------------------------------
	// Profile page: 2FA setup widget
	// -------------------------------------------------------------------------

	public function display_qr_code( WP_User $user ) {
		$secret         = get_user_meta( $user->ID, 'totp_secret', true );
		$verified       = (bool) get_user_meta( $user->ID, 'totp_verified', true );
		$pending_secret = get_user_meta( $user->ID, 'totp_pending_secret', true );
		?>
		<div class="application-2fa" id="application-2fa" style="margin-bottom:1rem;">
			<h2><?php _e( 'Two-factor authentication app', 'login-sec' ); ?></h2>

			<?php if ( current_user_can( 'manage_options' ) ) : ?>
				<div style="color:#aa0303;background:#ffd0d0;padding:10px;margin-bottom:1rem;" role="alert">
					<strong><?php _e( 'For administrators!', 'login-sec' ); ?></strong>
					<?php _e( 'For the codes to work correctly, it is necessary to correctly set the time zone settings in php.ini.', 'login-sec' ); ?>
					<br>
					<?php _e( 'If the user has lost the code, only the administrator can reset it using the "Delete Secret" button in the user profile.', 'login-sec' ); ?>
				</div>
			<?php endif; ?>

			<?php if ( $secret && $verified ) : ?>
				<!-- STATE: 2FA is active -->
				<div style="display:flex;align-items:center;gap:8px;margin-bottom:1rem;">
					<span style="font-size:1.4em;">&#x2705;</span>
					<strong><?php _e( 'Two-factor authentication is active.', 'login-sec' ); ?></strong>
				</div>
				<button id="regenerate-secret-button" data-user="<?php echo esc_attr( $user->ID ); ?>"
				        class="button button-secondary">
					<?php _e( 'Change 2FA device (regenerate secret)', 'login-sec' ); ?>
				</button>
				&nbsp;
				<button id="delete-secret-button" data-user="<?php echo esc_attr( $user->ID ); ?>"
				        class="button button-link-delete" style="color:#a00;">
					<?php _e( 'Delete secret', 'login-sec' ); ?>
				</button>

			<?php else : ?>
				<!-- STATE: 2FA not set up -->
				<div id="tfa-setup-area">
					<?php if ( ! $pending_secret ) : ?>
						<!-- Step 1: no pending secret yet -->
						<p><?php _e( 'Two-factor authentication is not configured.', 'login-sec' ); ?></p>
						<button id="generate-secret-button" data-user="<?php echo esc_attr( $user->ID ); ?>"
						        class="button button-primary">
							<?php _e( 'Set up 2FA', 'login-sec' ); ?>
						</button>

					<?php else :
						$name        = get_bloginfo( 'name' );
						$label       = urlencode( $user->user_login );
						$otpauth     = "otpauth://totp/{$label}?secret={$pending_secret}&issuer={$name}";
						$qr_code_url = 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' . urlencode( $otpauth );
						?>
						<!-- Step 2: scan QR and confirm -->
						<ol style="line-height:2;">
							<li><?php _e( 'Open your authenticator app (Google Authenticator, Authy, etc.).', 'login-sec' ); ?></li>
							<li><?php _e( 'Scan the QR code below.', 'login-sec' ); ?></li>
							<li><?php _e( 'Enter the 6-digit code from the app to confirm setup.', 'login-sec' ); ?></li>
						</ol>

						<img src="<?php echo esc_url( $qr_code_url ); ?>" alt="QR Code"
						     style="display:block;margin:1rem 0;border:1px solid #ddd;padding:4px;" />

						<p style="font-size:.85em;color:#555;">
							<?php _e( 'Or enter the key manually:', 'login-sec' ); ?>
							<code style="user-select:all;"><?php echo esc_html( $pending_secret ); ?></code>
						</p>

						<div id="tfa-confirm-wrap" style="margin-top:1rem;">
							<label for="tfa-confirm-code" style="display:block;font-weight:600;margin-bottom:4px;">
								<?php _e( 'Code from the app:', 'login-sec' ); ?>
							</label>
							<input type="text" id="tfa-confirm-code" maxlength="6" size="10"
							       placeholder="000000" autocomplete="one-time-code" inputmode="numeric"
							       style="font-size:1.2em;letter-spacing:.2em;width:8em;" />
							&nbsp;
							<button id="confirm-totp-button" data-user="<?php echo esc_attr( $user->ID ); ?>"
							        class="button button-primary">
								<?php _e( 'Confirm', 'login-sec' ); ?>
							</button>
							<span id="tfa-confirm-msg" style="margin-left:8px;font-weight:600;"></span>
						</div>

						<p style="margin-top:1rem;">
							<button id="generate-secret-button" data-user="<?php echo esc_attr( $user->ID ); ?>"
							        class="button button-link" style="color:#888;font-size:.85em;">
								<?php _e( 'Generate new QR code', 'login-sec' ); ?>
							</button>
						</p>
					<?php endif; ?>
				</div>
			<?php endif; ?>
		</div>
		<?php
	}

	// -------------------------------------------------------------------------
	// AJAX: generate a pending (unconfirmed) secret
	// -------------------------------------------------------------------------

	public function handle_generate_pending_secret() {
		if ( ! wp_verify_nonce( $_POST['nonce'] ?? '' ) ) {
			wp_send_json_error( [ 'message' => __( 'Security check failed.', 'login-sec' ) ] );
		}

		$target_user_id = absint( $_POST['id'] ?? 0 );
		if ( ! current_user_can( 'edit_user', $target_user_id ) ) {
			wp_send_json_error( [ 'message' => __( 'Not enough rights.', 'login-sec' ) ] );
		}

		$secret = Auth2FA::generate_secret( 32 );
		update_user_meta( $target_user_id, 'totp_pending_secret', $secret );

		wp_send_json_success( [
			'message' => __( 'Pending secret generated. Page will reload.', 'login-sec' ),
		] );
	}

	// -------------------------------------------------------------------------
	// AJAX: confirm pending secret — verify code, promote to active
	// -------------------------------------------------------------------------

	public function handle_confirm_totp_setup() {
		if ( ! wp_verify_nonce( $_POST['nonce'] ?? '' ) ) {
			wp_send_json_error( [ 'message' => __( 'Security check failed.', 'login-sec' ) ] );
		}

		$target_user_id = absint( $_POST['id'] ?? 0 );
		if ( ! current_user_can( 'edit_user', $target_user_id ) ) {
			wp_send_json_error( [ 'message' => __( 'Not enough rights.', 'login-sec' ) ] );
		}

		$pending_secret = get_user_meta( $target_user_id, 'totp_pending_secret', true );
		if ( empty( $pending_secret ) ) {
			wp_send_json_error( [ 'message' => __( 'No pending secret found. Please start setup again.', 'login-sec' ) ] );
		}

		$code = trim( $_POST['code'] ?? '' );
		if ( ! $this->verify_code_with_window( $pending_secret, $code ) ) {
			wp_send_json_error( [ 'message' => __( 'Invalid code. Please check your app and try again.', 'login-sec' ) ] );
		}

		// Code is correct — promote pending secret to active
		update_user_meta( $target_user_id, 'totp_secret', $pending_secret );
		update_user_meta( $target_user_id, 'totp_verified', 1 );
		delete_user_meta( $target_user_id, 'totp_pending_secret' );

		wp_send_json_success( [
			'message' => __( '2FA successfully activated! The page will reload.', 'login-sec' ),
		] );
	}

	// -------------------------------------------------------------------------
	// AJAX: regenerate secret (replace existing active 2FA)
	// Clears active secret; generates a new pending one; user must confirm again
	// -------------------------------------------------------------------------

	public function handle_secret_regeneration() {
		if ( ! wp_verify_nonce( $_POST['nonce'] ?? '' ) ) {
			wp_send_json_error( [ 'message' => __( 'Security check failed.', 'login-sec' ) ] );
		}

		$target_user_id = absint( $_POST['id'] ?? get_current_user_id() );
		if ( ! current_user_can( 'edit_user', $target_user_id ) ) {
			wp_send_json_error( [ 'message' => __( 'Not enough rights.', 'login-sec' ) ] );
		}

		delete_user_meta( $target_user_id, 'totp_secret' );
		delete_user_meta( $target_user_id, 'totp_verified' );

		$secret = Auth2FA::generate_secret( 32 );
		update_user_meta( $target_user_id, 'totp_pending_secret', $secret );

		wp_send_json_success( [
			'message' => __( 'A new QR code has been generated. Please scan and confirm it. The page will reload.', 'login-sec' ),
		] );
	}

	// -------------------------------------------------------------------------
	// AJAX: delete secret completely — disables 2FA
	// -------------------------------------------------------------------------

	public function handle_secret_delete() {
		if ( ! wp_verify_nonce( $_POST['nonce'] ?? '' ) ) {
			wp_send_json_error( [ 'message' => __( 'Security check failed.', 'login-sec' ) ] );
		}

		$target_user_id = absint( $_POST['id'] ?? 0 );
		if ( ! current_user_can( 'edit_user', $target_user_id ) ) {
			wp_send_json_error( [ 'message' => __( 'Not enough rights.', 'login-sec' ) ] );
		}

		delete_user_meta( $target_user_id, 'totp_secret' );
		delete_user_meta( $target_user_id, 'totp_verified' );
		delete_user_meta( $target_user_id, 'totp_pending_secret' );

		wp_send_json_success( [
			'message' => __( 'Secret removed. Page will reload.', 'login-sec' ),
		] );
	}

	// -------------------------------------------------------------------------
	// Scripts (profile page only)
	// -------------------------------------------------------------------------

	public function enqueue_scripts() {
		global $current_screen;

		if ( $current_screen->base !== 'profile' ) {
			return;
		}

		$nonce   = wp_create_nonce();
		$ajaxurl = esc_url( admin_url( 'admin-ajax.php' ) );

		wp_enqueue_script( 'jquery' );
		wp_add_inline_script( 'jquery', '
			jQuery(document).ready(function($) {

				// Generate / start setup
				$(document).on("click", "#generate-secret-button", function(e) {
					e.preventDefault();
					var btn = $(this);
					btn.prop("disabled", true).text("Generating\u2026");
					$.post("' . $ajaxurl . '", {
						action: "generate_pending_secret",
						id: btn.data("user"),
						nonce: "' . $nonce . '"
					}, function(response) {
						if (response.success) {
							location.reload();
						} else {
							alert(response.data.message);
							btn.prop("disabled", false).text("Set up 2FA");
						}
					});
				});

				// Confirm code after scanning QR
				$(document).on("click", "#confirm-totp-button", function(e) {
					e.preventDefault();
					var btn  = $(this);
					var code = $("#tfa-confirm-code").val().replace(/\s/g, "");
					var msg  = $("#tfa-confirm-msg");

					if (!/^\d{6}$/.test(code)) {
						msg.css("color", "#cc0000").text("Please enter a 6-digit code.");
						return;
					}

					btn.prop("disabled", true);
					msg.css("color", "#555").text("Checking\u2026");

					$.post("' . $ajaxurl . '", {
						action: "confirm_totp_setup",
						id: btn.data("user"),
						code: code,
						nonce: "' . $nonce . '"
					}, function(response) {
						if (response.success) {
							msg.css("color", "#246b24").text("\u2713 " + response.data.message);
							setTimeout(function() { location.reload(); }, 1500);
						} else {
							msg.css("color", "#cc0000").text("\u2717 " + response.data.message);
							btn.prop("disabled", false);
							$("#tfa-confirm-code").val("").focus();
						}
					});
				});

				// Enter key in code field
				$(document).on("keypress", "#tfa-confirm-code", function(e) {
					if (e.which === 13) { e.preventDefault(); $("#confirm-totp-button").trigger("click"); }
				});

				// Regenerate (replace active secret)
				$(document).on("click", "#regenerate-secret-button", function(e) {
					e.preventDefault();
					if (!confirm("This will invalidate your current 2FA. You will need to re-scan a new QR code. Continue?")) return;
					$.post("' . $ajaxurl . '", {
						action: "regenerate_secret",
						id: $(this).data("user"),
						nonce: "' . $nonce . '"
					}, function(response) {
						alert(response.data.message);
						location.reload();
					});
				});

				// Delete secret
				$(document).on("click", "#delete-secret-button", function(e) {
					e.preventDefault();
					if (!confirm("Are you sure you want to disable 2FA for this account?")) return;
					$.post("' . $ajaxurl . '", {
						action: "delete_secret",
						id: $(this).data("user"),
						nonce: "' . $nonce . '"
					}, function(response) {
						alert(response.data.message);
						location.reload();
					});
				});

			});
		' );
	}
}

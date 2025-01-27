<?php


defined( 'ABSPATH' ) or die( 'There`s nothing here!' );

class TwoFactorAuthorisation {

	public function __construct() {

	}

	public function add_actions() {
		add_action( 'login_form', [ $this, 'add_2fa_form' ] );
		add_filter( 'authenticate', [ $this, 'verify_totp_code' ], 100, 3 );
		// add_action( 'user_register', [ $this, 'save_totp_secret' ] );

		add_action( 'show_user_profile', [ $this, 'display_qr_code' ], 1, 1 );
		add_action( 'edit_user_profile', [ $this, 'display_qr_code' ], 1, 1 );

		add_action( "wp_ajax_regenerate_secret", [ $this, 'handle_secret_regeneration' ] );
		add_action( "wp_ajax_delete_secret", [ $this, 'handle_secret_delete' ] );

		add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_scripts' ], 99 );
	}

	// Генерация секретного ключа
	private function generate_secret( $length = 16 ) {
		return $this->base32_encode( random_bytes( $length ) );
	}

	// Генерация TOTP кода, 6 цифр каждые 30 сек
	private function generate_totp($secret) {
		// Устанавливаем шаг времени в 30 секунд
		$timeSlice = floor(current_time('timestamp') / 30);
		// Декодируем секретный ключ из Base32
		$secretKey = $this->base32_decode($secret);

		// Генерация HMAC
		$hmac = hash_hmac('SHA1', pack('N', $timeSlice), $secretKey, true);

		// Получаем смещение
		$offset = ord($hmac[19]) & 0x0F;

		// Вычисляем код
		$code = (
			        (ord($hmac[$offset]) & 0x7F) << 24 |
			        (ord($hmac[$offset + 1]) & 0xFF) << 16 |
			        (ord($hmac[$offset + 2]) & 0xFF) << 8 |
			        (ord($hmac[$offset + 3]) & 0xFF)
		        ) % 1000000; // 6-значный код

		return str_pad($code, 6, '0', STR_PAD_LEFT); // Возвращаем 6-значный код
	}

	// Кодирование в Base32
	private function base32_encode( $data ) {
		$base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$buffer      = '';
		$bitsLeft    = 0;
		$value       = 0;

		foreach ( str_split( $data ) as $char ) {
			$value    = ( $value << 8 ) | ord( $char );
			$bitsLeft += 8;

			while ( $bitsLeft >= 5 ) {
				$buffer   .= $base32chars[ ( $value >> ( $bitsLeft - 5 ) ) & 0x1F ];
				$bitsLeft -= 5;
			}
		}

		if ( $bitsLeft > 0 ) {
			$buffer .= $base32chars[ ( $value << ( 5 - $bitsLeft ) ) & 0x1F ];
		}

		return $buffer;
	}

	// Декодирование Base32
	private function base32_decode( $base32 ) {
		$base32      = strtoupper( $base32 );
		$base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$binary      = '';
		$buffer      = 0;
		$bitsLeft    = 0;

		for ( $i = 0; $i < strlen( $base32 ); $i ++ ) {
			$value = strpos( $base32chars, $base32[ $i ] );
			if ( $value === false ) {
				continue;
			}
			$buffer   <<= 5;
			$buffer   |= $value;
			$bitsLeft += 5;

			if ( $bitsLeft >= 8 ) {
				$binary   .= chr( ( $buffer >> ( $bitsLeft - 8 ) ) & 0xFF );
				$bitsLeft -= 8;
			}
		}

		return $binary;
	}

	// Добавление формы для ввода кода
	public function add_2fa_form() {
		echo wp_date('Y-m-d H:i:s');
		echo '<p>
                <label for="totp_code">' .
                __( 'Enter the 2FA code if you have one installed', 'login-sec' ) . ':
                </label>
               
                <input type="text" name="totp_code" id="totp_code" class="input" value="" size="20" />
              </p>';
	}

	// Проверка кода при входе
	public function verify_totp_code($user, $username, $password  ) {

		$user_id = username_exists( $username );
		$user_id = !empty($user_id) ? $user_id : email_exists( $username );
		if ( $user_id === false ) { // to exclude user: || $user_id == '1'
			return $user;
		}
		$secret = get_user_meta( $user_id, 'totp_secret', true );
		$code   = $_POST['totp_code'];

		$secret_code = Auth2FA::TOTP( $secret );
		if ( ! empty( $secret ) && $secret_code !== $code ) {
			return new WP_Error( 'invalid_totp', __( 'Invalid 2FA code.', 'login-sec' ) );
		}

		return $user;
	}

	// Сохранение секретного ключа для пользователя
	public function save_totp_secret( $user_id ) {
		$secret = Auth2FA::generate_secret(16);//$this->generate_secret();
		update_user_meta( $user_id, 'totp_secret', $secret );
	}

	// Отображение QR-кода
	public function display_qr_code( WP_User $user ) {
		// Если секрета нет, создаем новый
		if ( empty($secret) ) {
			// $this->save_totp_secret( $user->ID );
		}

		?>
			<div class="application-2fa" id="application-2fa" style="margin-bottom: 1rem;">
			<h2><?php _e( 'Two-factor authentication app', 'login-sec' ); ?></h2>

		    <?php if(current_user_can( 'manage_options' )): ?>
			<div class="alert alert-warning" role="alert" style="color: #aa0303; background: #ffd0d0; padding: 10px;">
				<strong><?php _e( 'For administrators!', 'login-sec' ); ?></strong>
				<?php _e( 'For the codes to work correctly, it is necessary to correctly set the time zone settings in php.ini.', 'login-sec' ); ?><br>
				<?php _e( 'If the user has lost the code, only the administrator can reset it using the "Delete Secret" button in the user profile.', 'login-sec' ); ?>
			</div>
			<?php endif; ?>
		<?

		// Получаем секретный ключ
		$secret = get_user_meta( $user->ID, 'totp_secret', true );
		if($secret) {
			$name        = get_bloginfo('name');
			$label       = urlencode( $user->user_login );
			$data        = "otpauth://totp/{$label}?secret={$secret}&issuer={$name}";
			$qr_code_url = "https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=" . urlencode( $data );
			echo '<h3>' . __( 'QR code to create 2FA', 'login-sec' ) . '</h3>';
			echo '<img src="' . esc_url( $qr_code_url ) . '" alt="QR Code" />';

			$totp = Auth2FA::TOTP($secret, 30);
			$expirationTime = Auth2FA::expire_time(30);

            echo '<br>';
			echo __( "Current Code", 'login-sec'). ": $totp".PHP_EOL;
			echo '<br>';
			echo __("Expire on", "login-sec") .': '. date("H:i:s", $expirationTime)." (".($expirationTime - time())."s remind)".PHP_EOL;
			echo '<br>';
		}

		echo '<button id="regenerate-secret-button" data-user="'.$user->ID.'" class="button button-primary">' .
		     __( 'Regenerate secret', 'login-sec' ) .
		     '</button> ';

		if($secret) {
			echo '<button id="delete-secret-button" data-user="' . $user->ID . '" class="button button-secondary">' .
			     __( 'Delete secret', 'login-sec' ) .
			     '</button>';
		}
		echo '</div>';
	}

	public function handle_secret_delete() {
		if ( ! wp_verify_nonce( $_POST['nonce'] ) ) {
			wp_send_json_error();
		}

		if ( current_user_can( 'edit_user', $_POST['id'] ) ) {
			//$user = get_user_by( 'id',  (absint($_POST['id'])) );
			delete_user_meta( $_POST['id'], 'totp_secret' );
			wp_send_json_success( [
				'message' => __( 'Secret removed. Page will reload.', 'login-sec' )
			] );
		} else {
			wp_send_json_error( [ 'message' => __( 'Not enough rights.', 'login-sec' ) ] );
		}
	}

	// Обработка перегенерации секрета
	public function handle_secret_regeneration() {

		if ( ! wp_verify_nonce( $_POST['nonce'] ) ) {
			wp_send_json_error();
		}

		if ( current_user_can( 'edit_user', get_current_user_id() ) ) {
			$this->save_totp_secret( get_current_user_id() );
			wp_send_json_success( [
				'message' => __( 'The secret has been regenerated. The page will reload.', 'login-sec' )
			] );
		} else {
			wp_send_json_error( [ 'message' => __( 'Not enough rights.', 'login-sec' ) ] );
		}
	}

	// Подключение скриптов
	public function enqueue_scripts() {
		global $current_screen;

		if($current_screen->base != 'profile') {
			return;
		}

		$nonce   = wp_create_nonce();
		$ajaxurl = esc_url( admin_url( 'admin-ajax.php' ) );

		wp_enqueue_script( 'jquery' );
		wp_add_inline_script( 'jquery', '
			// console.log("2fa js");
			jQuery(document).ready(function($) {
				$("#regenerate-secret-button").on("click", function(e) {
					e.preventDefault();
					$.post("' . $ajaxurl . '", { action: "regenerate_secret", id: $(this).data().user, nonce: "' . $nonce . '"}, function(response) {
						// console.log(response);
						if (response.success) {
							alert(response.data.message);
							location.reload();
						} else {
							alert(response.data.message);
						}
					});
				});
				
				$("#delete-secret-button").on("click", function(e) {
					e.preventDefault();
					// console.log($(this).data().user);
					$.post("' . $ajaxurl . '", { action: "delete_secret", id: $(this).data().user, nonce: "' . $nonce . '"}, function(response) {
						// console.log(response);
						if (response.success) {
							alert(response.data.message);
							location.reload();
						} else {
							alert(response.data.message);
						}
					});
				});
			});
		' );
	}
}
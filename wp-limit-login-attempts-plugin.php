<?php

declare(strict_types=1);

/**
 * Plugin Name: Security. Limiting login attempts + 2FA verification.
 * Description: WordPress Security Plugin. Automatically blocked IP for many attempts login tries. + add lightweight 2FA by code.
 * Version:     1.2.1
 * Author:      Aleksey Tikhomirov
 * Author URI:  http://rwsite.ru
 * Text Domain: login-sec
 * Domain Path: /languages
 *
 * Requires at least: 6.5
 * Tested up to: 7.2
 * Requires PHP: 8.3
 */
defined('ABSPATH') || exit('There`s nothing here!');

if (version_compare(PHP_VERSION, '8.3.0', '<')) {
    add_action('admin_notices', static function (): void {
        if (! current_user_can('activate_plugins')) {
            return;
        }

        echo '<div class="notice notice-error"><p>';
        esc_html_e('Security. Limiting login attempts requires PHP 8.3 or newer.', 'login-sec');
        echo '</p></div>';
    });

    return;
}

require_once __DIR__.'/inc/LoginSecuritySettings.php';
require_once __DIR__.'/LimitAttemptsAdmin.php';
require_once __DIR__.'/inc/Auth2FA.php';
require_once __DIR__.'/TwoFactorAuthorisation.php';

class LimitLoginAttempts
{
    public LoginSecuritySettings $settings;

    private ?WP_Error $error = null;

    protected ?string $ip = null;

    protected ?string $username = null;

    public function __construct()
    {
        $this->settings = LoginSecuritySettings::fromWordPress();
    }

    public function add_actions(): void
    {

        // filter login request
        add_filter('authenticate', $this->authenticate(...), 5, 3);

        // add error form animation
        add_filter('shake_error_codes', fn ($codes): array => array_merge($codes, ['blocked']));

        // change login title
        add_filter('login_title', fn ($login_title, $title): string => __('Enter the site', 'login-sec').' / '.get_bloginfo('name', 'display'), 10, 2);

        // Add notices to woocommerce login page
        add_action('wp_head', $this->add_wc_notices(...));

        // settings
        add_action('admin_init', function (): void {
            (new LimitAttemptsAdmin($this->settings))->add_actions();
        });

        add_action('wp_dashboard_setup', function (): void {
            if (! current_user_can('manage_options')) {
                return;
            }

            wp_add_dashboard_widget('limit_login', __('Login attempts', 'login-sec'), $this->dashboard_widget(...));
        });

        add_action('init', function (): void {
            // if neither WordPress admin nor running from wp-cli, exit quickly to prevent performance impact
            if (! is_admin() && ! (defined('WP_CLI') && WP_CLI)) {
                return;
            }

            load_plugin_textdomain('login-sec', false, dirname(plugin_basename(__FILE__)).'/languages/');
        });
    }

    public function add_wc_notices(): void
    {
        if (! function_exists('is_account_page') || ! function_exists('wc_add_notice')) {
            return;
        }

        if (is_account_page() && $this->error instanceof WP_Error) {
            wc_add_notice($this->error->get_error_message(), 'error');
        }
    }

    public function authenticate(?WP_User $user, ?string $username, ?string $password = null): WP_User|WP_Error|null
    {
        if ($username === null || $username === '' || $password === null || $password === '') {
            return $user;
        }

        $time_limit = (int) $this->settings->time_limit;
        $attempts_limit = (int) $this->settings->attempts_limit;

        $this->ip = $this->get_ip_address();
        $this->username = $username;

        $list = $this->loadAuthList($this->ip ?? '');

        $time = current_time('timestamp');

        $ipKey = $this->ip ?? '';
        $ipAttempts = $list[$ipKey] ?? [];
        $time_difference = $ipAttempts !== []
            ? $time - (int) array_key_last($ipAttempts)
            : $time_limit;

        $list[$ipKey][$time] = $username;
        $allow = count($list[$ipKey]) < $attempts_limit;

        if ($time_difference < $time_limit) {
            // Remove default WP authentication filters
            remove_filter('authenticate', 'wp_authenticate_username_password', 20);
            remove_filter('authenticate', 'wp_authenticate_email_password', 20);
            $user = $this->add_error(sprintf(__('Too many login attempts in less than %s seconds.', 'login-sec'), $time_limit));
        }

        if (! $allow) {

            // Remove default WP authentication filters
            remove_filter('authenticate', 'wp_authenticate_username_password', 20);
            remove_filter('authenticate', 'wp_authenticate_email_password', 20);

            $user = $this->add_error(__('Too many login attempts. Your IP is blocked for a day.', 'login-sec'));

            set_transient('auth_'.$this->ip, json_encode($list), DAY_IN_SECONDS);
            $this->notify_by_mail($username);

            if (defined('XMLRPC_REQUEST') && constant('XMLRPC_REQUEST') === true) {
                header('HTTP/1.0 403 Forbidden');
                exit;
            }
        } else {
            // set_transient('auth_' . $this->ip, json_encode($list), DAY_IN_SECONDS);
            delete_transient('auth_'.$this->ip);
        }

        return $user;
    }

    protected function add_error(string $msg): WP_Error
    {
        $this->error ??= new WP_Error();
        $this->error->add('blocked', '<strong>Error: </strong>'.$msg);
        ob_start();
        trigger_error($msg.sprintf('IP: %s, login: %s', $this->ip, $this->username), E_USER_WARNING);
        ob_clean();

        return $this->error;
    }

    public function get_ip_address(): string
    {
        $this->ip = isset($_SERVER['REMOTE_ADDR']) && is_string($_SERVER['REMOTE_ADDR'])
            ? $_SERVER['REMOTE_ADDR']
            : '0.0.0.0';
        $headers = [
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_CF_CONNECTING_IP',
            'HTTP_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_FORWARDED',
            'HTTP_VIA',
            'HTTP_X_COMING_FROM',
            'HTTP_COMING_FROM',
            'REMOTE_ADDR',
        ];
        foreach ($headers as $header) {
            if (isset($_SERVER[$header]) && is_string($_SERVER[$header]) && $_SERVER[$header] !== '') {
                $this->ip = $_SERVER[$header];
            }
        }

        return $this->ip;
    }

    /**
     * @return array<string, array<int, string>>
     */
    private function loadAuthList(string $ip): array
    {
        if ($ip === '') {
            return [];
        }

        $raw = get_transient('auth_'.$ip);
        if (! is_string($raw) || $raw === '') {
            return [];
        }

        $decoded = json_decode($raw, true);
        if (! is_array($decoded)) {
            return [];
        }

        /** @var array<string, array<int, string>> $decoded */
        return $decoded;
    }

    public function dashboard_widget(): void
    {
        global $wpdb;

        $html = sprintf(
            '<div class="bg-light"><p>%s</p></div>',
            __('Last login attempts (max. 20 items)', 'login-sec'),
        );
        $html .= sprintf(
            '<div class="bg-light"><p>%s<code>%s</code></p></div>',
            __('Your IP:', 'login-sec'),
            $this->get_ip_address(),
        );

        if (wp_using_ext_object_cache()) {
            $msg = 'The site uses external caching. The logs is not available, to remove the blocking, clear the cache.';
            $html .= '<div class="status-label status-request-failed">'.$msg.'</div>';
            echo $html;

            return;
        }

        $sql = "SELECT * FROM `{$wpdb->options}` WHERE `option_name` REGEXP '_transient_auth_*' LIMIT 100;";
        $result = $wpdb->get_results($sql);
        if (empty($result)) {
            echo $html;

            return;
        }

        $html .= '<table class="wp-list-table widefat fixed striped table-view-list">';
        $html .= '<tr><th>IP</th><th>login</th><th>time</th></tr>';

        usort($result, function (object $a, object $b): int {
            return $this->latestAttemptTimestamp($a) <=> $this->latestAttemptTimestamp($b);
        });

        $result = array_slice($result, 0, 20);
        foreach ($result as $object) {
            $rows = $this->parseTransientRow($object);
            foreach ($rows as $row) {
                $html .= '<tr>';
                $html .= '<td>'.esc_html($row['ip']).'</td>';
                $html .= '<td>'.esc_html($row['login']).'</td>';
                $formatted = wp_date('d.m.Y H:i:s', $row['time']);
                $html .= '<td>'.esc_html(is_string($formatted) ? $formatted : (string) $row['time']).'</td>';
                $html .= '</tr>';
            }
        }

        $html .= '</table>';
        echo $html;
    }

    protected function notify_by_mail(string $username): void
    {
        if ($this->settings->notify_user_by_mail !== 'yes') {
            return;
        }

        $user_id = username_exists($username);
        if ($user_id === false) {
            $user_id = email_exists($username);
        }

        if ($user_id === false) {
            return;
        }

        $user = get_user_by('id', $user_id);
        if (! $user instanceof WP_User) {
            return;
        }

        wp_mail(
            $user->user_email,
            __('Login attempts', 'login-sec'),
            'Обнаружена попытка входа с неправильным паролем!'.' IP: '.$this->ip,
        );
    }

    private function latestAttemptTimestamp(object $row): int
    {
        $parsed = $this->parseTransientRow($row);
        $last = end($parsed);

        return is_array($last) ? $last['time'] : 0;
    }

    /**
     * @return list<array{ip: string, login: string, time: int}>
     */
    private function parseTransientRow(object $row): array
    {
        if (! property_exists($row, 'option_value') || ! is_string($row->option_value)) {
            return [];
        }

        $decoded = json_decode($row->option_value, true);
        if (! is_array($decoded)) {
            return [];
        }

        $output = [];
        foreach ($decoded as $ip => $attempts) {
            if (! is_string($ip) || ! is_array($attempts)) {
                continue;
            }

            foreach ($attempts as $time => $login) {
                if (! is_scalar($login)) {
                    continue;
                }

                $output[] = [
                    'ip' => $ip,
                    'login' => (string) $login,
                    'time' => (int) $time,
                ];
            }
        }

        return $output;
    }
}

(new LimitLoginAttempts())->add_actions();
(new TwoFactorAuthorisation())->add_actions();

<?php
/**
 * Plugin Name: Security. Limiting login attempts.
 * Description: WordPress Limit login attempts Plugin. Automatically blocked IP for many attempts login trys.
 * Version:     1.0.0
 * Author:      Aleksey Tikhomirov
 * Author URI:  http://rwsite.ru
 * Text Domain: login
 * Domain Path: /languages
 * 
 * Requires at least: 4.6
 * Tested up to: 6.3
 * Requires PHP: 8.0+
 */

defined('ABSPATH') or die('Nothing here!');

require_once 'LimitAttemptsAdmin.php';

class LimitLoginAttempts
{
    public object $settings;
    private WP_Error|null $error;
    protected string|null $ip;
    protected string|null $username;

    public function __construct()
    {
        $this->settings = (object)[
            'time_limit'     => get_option('time_limit', 5),
            'attempts_limit' => get_option('attempts_limit', 5),
            'block_period'   => get_option('block_period', DAY_IN_SECONDS),
        ];
    }

    public function add_actions()
    {

        // filter login request
        add_filter('authenticate', [$this, 'authenticate'], 5, 3);

        // add error form animation
        add_filter('shake_error_codes', fn($codes) => array_merge($codes, ['blocked']));

        // change login title
        add_filter('login_title', fn($login_title, $title) => __('Enter the site', 'login') . ' / ' . get_bloginfo('name', 'display'), 10, 2);

        // Add notices to woocommerce login page
        add_action('wp_head', array($this, 'add_wc_notices'));

        // settings
        add_action( 'admin_init', function (){
            (new LimitAttemptsAdmin($this->settings))->add_actions();
        });
    }


    public function add_wc_notices()
    {
        if (!function_exists('is_account_page') || !function_exists('wc_add_notice')) {
            return;
        }

        if (is_account_page() && !empty($this->error)) {
            wc_add_notice($this->error->get_error_message(), 'error');
        }
    }


    public function authenticate( ?WP_User $user, $username, $password = null)
    {
        if (empty($username) || empty($password)) {
            return $user;
        }

        console_log([$user, $username, $password]);

        $time_limit = $this->settings->time_limit; // sec
        $attempts_limit = $this->settings->attempts_limit; // attempts

        $this->ip = $this->get_ip_address();
        $this->username = $username;

        delete_transient('auth_'. $this->ip);
        
        // [ip =>['time' => 'login']]]
        $list = get_transient('auth_' . $this->ip);
        $list = !empty($list) && is_string($list) ? json_decode($list, true) : [];
        $time = current_time('timestamp', false);
        
        $time_difference = !empty($list[$this->ip]) ? $time - array_key_last($list[$this->ip]) : $time_limit;

        $list[$this->ip][$time] = $username;
        $allow = count($list[$this->ip]) < $attempts_limit;
        
        // console_log(['ip_list' => $list, 'diff' => $time_difference, 'settings_limit' => $time_limit, '$allow' => $allow]);
        
        if ( $time_difference > $time_limit) {
            // Remove default WP authentication filters
            remove_filter('authenticate', 'wp_authenticate_username_password', 20);
            remove_filter('authenticate', 'wp_authenticate_email_password', 20);
            $user = $this->add_error(sprintf(__('Too many login attempts in less than %s seconds.','login'), $time_limit));
        }

        if (!$allow) {

            // Remove default WP authentication filters
            remove_filter('authenticate', 'wp_authenticate_username_password', 20);
            remove_filter('authenticate', 'wp_authenticate_email_password', 20);

            $user = $this->add_error(__('Too many login attempts. Your IP is blocked for a day.', 'login'));

            if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
                header('HTTP/1.0 403 Forbidden');
                exit;
            }
        } else {
            set_transient('auth_' . $this->ip, json_encode($list), DAY_IN_SECONDS);
        }

        return $user;
    }

    protected function add_error($msg)
    {
        $this->error = $this->error ?? new WP_Error();
        $this->error->add('blocked', "<strong>Error: Your IP is blocked.</strong> $msg.");

        trigger_error($msg . sprintf('IP: %s, login: %s', $this->ip, $this->username), E_USER_WARNING);

        return $this->error;
    }

    public function get_ip_address()
    {
        $this->ip = $_SERVER['REMOTE_ADDR'];
        $headers = array(
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
            'REMOTE_ADDR'
        );
        foreach ($headers as $header) {
            if (isset($_SERVER[$header])) {
                $this->ip = $_SERVER[$header];
            }
        }
        return $this->ip;
    }
}


$sec = new LimitLoginAttempts();
$sec->add_actions();
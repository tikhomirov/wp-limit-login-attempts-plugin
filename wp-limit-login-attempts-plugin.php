<?php
/**
 * Plugin Name: Security. Limiting login attempts.
 * Description: WordPress Limit login attempts Plugin. Automatically blocked IP for many attempts login trys.
 * Version:     1.0.2
 * Author:      Aleksey Tikhomirov
 * Author URI:  http://rwsite.ru
 * Text Domain: login
 * Domain Path: /languages
 * 
 * Requires at least: 4.6
 * Tested up to: 6.3
 * Requires PHP: 7.4+
 */

defined('ABSPATH') or die('There`s nothing here!');

require_once 'LimitAttemptsAdmin.php';

class LimitLoginAttempts
{
    public object $settings;

    /** @var WP_Error|null  */
    private ?WP_Error $error;

    /** @var string|null  */
    protected ?string $ip;

    /** @var string|null  */
    protected ?string $username;

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
        
        add_action('wp_dashboard_setup', function () {
            if (!current_user_can('manage_options')) {
                return;
            }
            wp_add_dashboard_widget('limit_login', __('login attempts', 'login'), [$this, 'dashboard_widget']);
        });


        add_action( 'init', function() {
            // if neither WordPress admin nor running from wp-cli, exit quickly to prevent performance impact
            if ( !is_admin() && ! ( defined( 'WP_CLI' ) && WP_CLI ) ) return;

            load_plugin_textdomain( 'login', false, dirname( plugin_basename( __FILE__ ) ) . '/languages/' );
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

        $time_limit = $this->settings->time_limit; // sec
        $attempts_limit = $this->settings->attempts_limit; // attempts

        $this->ip = $this->get_ip_address();
        $this->username = $username;

        $list = get_transient('auth_' . $this->ip);
        $list = !empty($list) && is_string($list) ? json_decode($list, true) : [];
        $time = current_time( 'timestamp' );
        
        $time_difference = !empty($list[$this->ip]) ? $time - array_key_last($list[$this->ip]) : (int) $time_limit;

        $list[$this->ip][$time] = $username;
        $allow = count($list[$this->ip]) < $attempts_limit;
        
        if ( $time_difference < $time_limit) {
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

            set_transient('auth_' . $this->ip, json_encode($list), DAY_IN_SECONDS);

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
        $this->error->add('blocked', '<strong>Error: </strong>' . $msg );

        trigger_error($msg . sprintf('IP: %s, login: %s', $this->ip, $this->username), E_USER_WARNING);

        return $this->error;
    }

    public function get_ip_address()
    {
        $this->ip = $_SERVER['REMOTE_ADDR'];
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
            'REMOTE_ADDR'
        ];
        foreach ($headers as $header) {
            if (isset($_SERVER[$header])) {
                $this->ip = $_SERVER[$header];
            }
        }
        return $this->ip;
    }
    
    public function dashboard_widget():void
    {
        global $wpdb;

        $html = sprintf("<div class=\"bg-light\"><p>%s</p></div>",
        __('Last login attempts (max. 20 items)','login'));
        $html .= sprintf("<div class=\"bg-light\"><p>Your IP: <code>%s</code></p></div>",
           $this->get_ip_address());

        if ( wp_using_ext_object_cache() ) {
            $html .= '<div class="status-label status-request-failed">The site uses external caching. The logs is not available, to remove the blocking, clear the cache.</div>';
            echo $html;
            return;
        }

        $sql = "SELECT * FROM `rwp_options` WHERE `option_name` REGEXP '_transient_auth_*' LIMIT 100;";
        $result = $wpdb->get_results($sql);
        if(empty($result)){
            echo $html;
            return;
        }

        $html .= '<table class="wp-list-table widefat fixed striped table-view-list">';
        $html .= '<tr><th>IP</th><th>login</th><th>time</th></tr>';

        usort($result, function ($a, $b){
            $a_val = json_decode($a->option_value, true);
            $a_ip = array_key_first($a_val);
            $a_data = $a_val[$a_ip] ?? [];
            $a_time = array_key_last($a_data);

            $b_val = json_decode($b->option_value, true);
            $b_ip = array_key_first($b_val);
            $b_data = $a_val[$b_ip] ?? [];
            $b_time = array_key_last($b_data);
            return $a_time <=> $b_time;
        } );

        $result = array_slice($result, 0, 20);
        foreach ($result as $object) {
            $value = json_decode($object->option_value, true);
            $ip = array_key_first($value);
            $data = $value[$ip];
            // echo '<pre>'; var_dump($value); echo '</pre>';wp_die();
            foreach ($data as $time => $login) {
                $html .= '<tr>';
                $html .= '<td>'.$ip.'</td>';
                $html .= '<td>' . $login.'</td>';
                $html .= '<td>' . wp_date('d.m.Y H:i:s', $time).'</td>';
                $html .= '</tr>';
            }
        }
        $html .= '</table>';
        echo $html;
    }
}


$sec = new LimitLoginAttempts();
$sec->add_actions();
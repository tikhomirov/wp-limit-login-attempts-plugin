<?php

declare(strict_types=1);

/**
 * Settings for plugin
 */
defined('ABSPATH') || exit('There`s nothing here!');

class LimitAttemptsAdmin
{
    public function __construct(protected LoginSecuritySettings $settings) {}

    public function add_actions(): void
    {
        $this->settings_init();
    }

    public function settings_init(): void
    {
        global $pagenow;

        add_settings_section(
            'login-section',
            __('Limit login attempts', 'login-sec'),
            static function (): void {},
            'general',
        );

        add_settings_field(
            'attempts_limit',
            '<label for="attempts_limit">'.__('Limit login attempts', 'login-sec').'</label>',
            function (): void {
                echo '<input type="text" name="attempts_limit" value="'.$this->settings->attempts_limit.'">';
                echo sprintf(
                    '<p class="description">%s</p>',
                    __('Maximum number of login attempts. After this, the IP will be blocked for a day.', 'login-sec'),
                );
            },
            'general',
            'login-section',
        );

        add_settings_field(
            'time_limit',
            '<label for="time_limit">'.__('Limit time', 'login-sec').'</label>',
            function (): void {
                echo '<input type="text" name="time_limit" value="'.$this->settings->time_limit.'">';
                echo '<p class="description">'.__(
                    'Time limit in seconds for 1 authorization attempt.',
                    'login-sec',
                ).'</p>';
            },
            'general',
            'login-section',
        );

        add_settings_field(
            'block_period',
            '<label for="block_period">'.__('Block time', 'login-sec').'</label>',
            function (): void {
                echo '<input type="text" name="block_period" value="'.$this->settings->block_period.'">';
                echo '<p class="description">'.__('Blocking period, in milliseconds.', 'login-sec').'</p>';
            },
            'general',
            'login-section',
        );

        register_setting('general', 'attempts_limit', [
            'sanitize_callback' => 'sanitize_title_with_dashes',
        ]);
        register_setting('general', 'time_limit', [
            'sanitize_callback' => 'sanitize_title_with_dashes',
        ]);
        register_setting('general', 'block_period', [
            'sanitize_callback' => 'sanitize_title_with_dashes',
        ]);

    }
}

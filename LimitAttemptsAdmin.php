<?php
/**
 * Settings for plugin
 */

class LimitAttemptsAdmin
{
    protected object $settings;

    public function __construct(object $settings)
    {
        $this->settings = $settings;
    }
    public function add_actions(){
        $this->settings_init();
    }

    public function settings_init()
    {
        global $pagenow;

        add_settings_section('login-section', 'Login', __return_empty_array(), 'general');

        add_settings_field(
            'attempts_limit',
            '<label for="attempts_limit">' . __('Limit attempts', 'login') . '</label>',
            function (){
                echo '<input type="text" name="attempts_limit" value="' . $this->settings->attempts_limit . '">';
                echo sprintf('<p class="description">%s</p>',
                    __('Максимальное кол-во попыток войти в систему. После этого IP будет заблокирован на сутки','login')
                );
            },
            'general',
            'login-section'
        );

        add_settings_field('time_limit',
            '<label for="time_limit">' . __('Limit time', 'login') . '</label>',
            function (){
                echo '<input type="text" name="time_limit" value="' . $this->settings->time_limit . '">';
                echo '<p class="description">'. __('Временной лимит в секундах на 1 попытку авторизации','login') .'</p>';
            },
            'general',
            'login-section'
        );

        add_settings_field('block_period',
            '<label for="block_period">' . __('Block time', 'login') . '</label>',
            function (){
                echo '<input type="text" name="block_period" value="' . $this->settings->block_period . '">';
                echo '<p class="description">'.__('Период блокировки','login').'</p>';
            },
            'general',
            'login-section'
        );

        register_setting('general', 'attempts_limit', 'sanitize_title_with_dashes');
        register_setting('general', 'time_limit', 'sanitize_title_with_dashes');
        register_setting('general', 'block_period', 'sanitize_title_with_dashes');

    }

}
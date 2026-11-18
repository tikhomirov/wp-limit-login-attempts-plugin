<?php

declare(strict_types=1);

/**
 * Plugin settings loaded from wp_options.
 */
final class LoginSecuritySettings
{
    public function __construct(
        public int|string $time_limit,
        public int|string $attempts_limit,
        public int|string $block_period,
        public string $notify_user_by_mail,
    ) {}

    public static function fromWordPress(): self
    {
        return new self(
            time_limit: self::optionScalar(get_option('time_limit', 5), 5),
            attempts_limit: self::optionScalar(get_option('attempts_limit', 5), 5),
            block_period: self::optionScalar(get_option('block_period', DAY_IN_SECONDS), DAY_IN_SECONDS),
            notify_user_by_mail: self::optionString(get_option('notify_user_by_mail', 'yes'), 'yes'),
        );
    }

    private static function optionScalar(mixed $value, int|string $default): int|string
    {
        if (is_int($value) || is_string($value)) {
            return $value;
        }

        return $default;
    }

    private static function optionString(mixed $value, string $default): string
    {
        if (is_string($value)) {
            return $value;
        }

        if (is_scalar($value)) {
            return (string) $value;
        }

        return $default;
    }
}

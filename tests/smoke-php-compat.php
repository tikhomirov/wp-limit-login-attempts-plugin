<?php

declare(strict_types=1);

/**
 * Runtime smoke test without WordPress (Auth2FA / TOTP math only).
 * Composer: `composer test` runs this script on default PHP, 8.4, and 8.5 when available.
 */
$root = dirname(__DIR__);
require $root.'/inc/Auth2FA.php';

$secret = Auth2FA::generate_secret(32);
$timeSlice = (int) floor(time() / 30);
$code = Auth2FA::TOTP_at($secret, $timeSlice);

if (strlen($code) !== 6 || ! ctype_digit($code)) {
    fwrite(STDERR, "Invalid TOTP code format\n");
    exit(1);
}

$decoded = Auth2FA::base32_decode($secret);
if ($decoded === '') {
    fwrite(STDERR, "base32_decode failed\n");
    exit(1);
}

if (Auth2FA::TOTP_at($secret, $timeSlice) !== $code) {
    fwrite(STDERR, "TOTP_at not deterministic\n");
    exit(1);
}

$binary = PHP_BINARY !== '' ? PHP_BINARY : 'unknown';
fwrite(STDOUT, "smoke-php-compat ok ({$binary}, PHP ".PHP_VERSION.")\n");

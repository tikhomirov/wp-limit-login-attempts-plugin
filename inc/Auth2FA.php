<?php

declare(strict_types=1);

/**
 * Auth2FA Service
 */
final class Auth2FA
{
    public static function TOTP(string $secret, int $timeSlice = 30): string
    {
        $timeSliceBasedValue = (int) floor(time() / $timeSlice);

        return self::TOTP_at($secret, $timeSliceBasedValue);
    }

    /**
     * Generate TOTP code for a specific pre-computed time slice value.
     */
    public static function TOTP_at(string $secret, int $timeSliceValue): string
    {
        $secretKey = self::base32_decode($secret);
        $data = pack('J', $timeSliceValue);
        $hash = hash_hmac('sha1', $data, $secretKey, true);
        $offset = ord($hash[19]) & 0xF;
        $otp = (
            ((ord($hash[$offset]) & 0x7F) << 24) |
            ((ord($hash[$offset + 1]) & 0xFF) << 16) |
            ((ord($hash[$offset + 2]) & 0xFF) << 8) |
            (ord($hash[$offset + 3]) & 0xFF)
        ) % 1_000_000;

        return str_pad((string) $otp, 6, '0', STR_PAD_LEFT);
    }

    public static function expire_time(int $timeSlice = 30): int
    {
        $timeSliceBasedValue = (int) floor(time() / $timeSlice);

        return ($timeSliceBasedValue + 1) * $timeSlice;
    }

    public static function HOTP(string $secret, int $counter): string
    {
        $secretKey = self::base32_decode($secret);
        $packed = pack('N*', 0).pack('N*', $counter);
        $hash = hash_hmac('sha1', $packed, $secretKey, true);
        $offset = ord($hash[19]) & 0xF;
        $code = (
            ((ord($hash[$offset]) & 0x7F) << 24) |
            ((ord($hash[$offset + 1]) & 0xFF) << 16) |
            ((ord($hash[$offset + 2]) & 0xFF) << 8) |
            (ord($hash[$offset + 3]) & 0xFF)
        ) % 1_000_000;

        return str_pad((string) $code, 6, '0', STR_PAD_LEFT);
    }

    public static function generate_secret(int $length = 32): string
    {
        $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $secret = '';
        $maxIndex = strlen($characters) - 1;
        for ($i = 0; $i < $length; $i++) {
            $secret .= $characters[random_int(0, $maxIndex)];
        }

        return $secret;
    }

    public static function base32_decode(string $str): string
    {
        $str = strtoupper($str);
        $str = str_replace([' ', '-'], '', $str);

        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $map = array_flip(str_split($chars));
        $data = '';
        $len = strlen($str);
        $buffer = 0;
        $bufferSize = 0;
        for ($i = 0; $i < $len; $i++) {
            $char = strtoupper($str[$i]);
            if (! isset($map[$char])) {
                continue;
            }

            $byte = $map[$char];
            $buffer = ($buffer << 5) | $byte;
            $bufferSize += 5;
            if ($bufferSize >= 8) {
                $bufferSize -= 8;
                $data .= chr(($buffer >> $bufferSize) & 0xFF);
            }
        }

        return $data;
    }
}

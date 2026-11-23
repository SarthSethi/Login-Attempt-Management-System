package com.example.loginmonitoring.service;

/**
 * Everything known about one login attempt before the password is checked.
 *
 * @param ip        visitor IP (from {@code ClientIpResolver})
 * @param email     the email typed into the form, already cleaned (lower case, trimmed)
 * @param userAgent the browser's User-Agent header (may be null)
 * @param simulated true when created by the attack simulator
 */
public record AttemptContext(String ip, String email, String userAgent, boolean simulated) {

    public static AttemptContext real(String ip, String rawEmail, String userAgent) {
        return new AttemptContext(ip, LoginAttemptService.cleanEmail(rawEmail), userAgent, false);
    }

    public static AttemptContext simulated(String ip, String rawEmail, String userAgent) {
        return new AttemptContext(ip, LoginAttemptService.cleanEmail(rawEmail), userAgent, true);
    }
}

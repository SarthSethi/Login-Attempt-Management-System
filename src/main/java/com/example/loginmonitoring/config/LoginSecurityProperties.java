package com.example.loginmonitoring.config;

import java.time.Duration;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Settings for the detection rules (prefix "app.security"). All windows are rolling windows.
 *
 * @param maxFailedAttempts    Rule 1 - failures for ONE account from ONE IP before that pair is locked (5)
 * @param monitoringWindow     window in which failures are counted (10 minutes)
 * @param blockDuration        length of a first lock / block (15 minutes)
 * @param ipMaxAccounts        Rule 2 - different accounts failing from one IP = credential stuffing (4)
 * @param ipMaxFailures        Rule 3 - failures from one IP for any accounts (10)
 * @param accountMaxFailures   Rule 4 - failures for one account from many IPs (8) ...
 * @param accountMinIps        ... coming from at least this many different IPs (3)
 * @param repeatBlockDurations Rule 5 - block length for the 2nd, 3rd, ... automatic block of an IP (1h, 24h)
 * @param repeatWindow         blocks within this period count as "repeat" (24 hours)
 * @param knownIpPeriod        an IP the owner logged in from within this period stays allowed
 *                             while the account is under a distributed attack (90 days)
 */
@ConfigurationProperties(prefix = "app.security")
public record LoginSecurityProperties(
        @DefaultValue("5") int maxFailedAttempts,
        @DefaultValue("10m") Duration monitoringWindow,
        @DefaultValue("15m") Duration blockDuration,
        @DefaultValue("4") int ipMaxAccounts,
        @DefaultValue("10") int ipMaxFailures,
        @DefaultValue("8") int accountMaxFailures,
        @DefaultValue("3") int accountMinIps,
        @DefaultValue({"1h", "24h"}) List<Duration> repeatBlockDurations,
        @DefaultValue("24h") Duration repeatWindow,
        @DefaultValue("90d") Duration knownIpPeriod) {

    /** Block length for the n-th automatic block (n = 1, 2, 3, ...). */
    public Duration blockDurationForLevel(int level) {
        if (level <= 1 || repeatBlockDurations == null || repeatBlockDurations.isEmpty()) {
            return blockDuration;
        }
        int index = Math.min(level - 2, repeatBlockDurations.size() - 1);
        return repeatBlockDurations.get(index);
    }
}

package com.example.loginmonitoring.dto;

import java.time.LocalDateTime;

import com.example.loginmonitoring.entity.BlockSource;

/** One row of a "Blocked IP addresses" table. */
public record BlockedIpView(
        Long id,
        String ipAddress,
        LocalDateTime blockedAt,
        LocalDateTime expiresAt,
        String remainingTime,
        boolean active,
        String reason,
        BlockSource source,
        int level,
        boolean permanent,
        boolean simulated,
        String createdBy,
        String liftedBy) {

    public String status() {
        if (active) {
            return permanent ? "BANNED" : "ACTIVE";
        }
        return liftedBy != null ? "LIFTED" : "EXPIRED";
    }
}

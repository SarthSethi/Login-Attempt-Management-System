package com.example.loginmonitoring.dto;

import java.time.LocalDateTime;

import com.example.loginmonitoring.entity.LoginOutcome;

/** Minimal attempt data used to draw the activity chart. */
public record TimeOutcome(LocalDateTime attemptedAt, LoginOutcome outcome) {
}

package com.example.loginmonitoring.entity;

public enum LoginOutcome {
    /** Correct email and password. */
    SUCCESS,
    /** Wrong password, unknown email or disabled account. */
    FAILED,
    /** Request rejected because the IP was blocked; credentials were never checked. */
    BLOCKED
}

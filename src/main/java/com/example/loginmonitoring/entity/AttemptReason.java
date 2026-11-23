package com.example.loginmonitoring.entity;

/**
 * Why an attempt failed or was rejected. Stored for the administrator only; the login page
 * never tells a visitor whether the email or the password was wrong.
 */
public enum AttemptReason {
    WRONG_PASSWORD("Wrong password"),
    UNKNOWN_EMAIL("No such account"),
    ACCOUNT_DISABLED("Account disabled"),
    IP_BLOCKED("IP address blocked"),
    ACCOUNT_IP_LOCKED("Account locked for this IP"),
    ACCOUNT_LOCKED("Account under attack - new locations paused");

    private final String label;

    AttemptReason(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}

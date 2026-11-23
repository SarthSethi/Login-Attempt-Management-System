package com.example.loginmonitoring.entity;

/** Warning signs found on a SUCCESSFUL login. Each flag adds to the login's risk score. */
public enum RiskFlag {
    AFTER_FAILURES("After failed attempts", 3),
    NEW_COUNTRY("New country", 2),
    VPN_OR_HOSTING("VPN / data centre IP", 2),
    AUTOMATED_CLIENT("Automated tool", 2),
    NEW_DEVICE("New device", 1);

    private final String label;
    private final int score;

    RiskFlag(String label, int score) {
        this.label = label;
        this.score = score;
    }

    public String getLabel() {
        return label;
    }

    public int getScore() {
        return score;
    }
}

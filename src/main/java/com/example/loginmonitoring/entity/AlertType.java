package com.example.loginmonitoring.entity;

public enum AlertType {
    BRUTE_FORCE("Brute force on one account"),
    CREDENTIAL_STUFFING("Credential stuffing"),
    HIGH_VOLUME("High volume of failures"),
    DISTRIBUTED_ATTACK("Distributed attack on one account"),
    SUSPICIOUS_LOGIN("Suspicious successful login"),
    USER_REPORTED("Login reported by account owner");

    private final String label;

    AlertType(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}

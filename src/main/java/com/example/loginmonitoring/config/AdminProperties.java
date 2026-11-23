package com.example.loginmonitoring.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Administrator account created at startup. Values come from the
 * ADMIN_NAME, ADMIN_EMAIL and ADMIN_PASSWORD environment variables.
 */
@ConfigurationProperties(prefix = "app.admin")
public record AdminProperties(
        @DefaultValue("Administrator") String name,
        String email,
        String password) {

    public boolean isConfigured() {
        return email != null && !email.isBlank() && password != null && !password.isBlank();
    }
}

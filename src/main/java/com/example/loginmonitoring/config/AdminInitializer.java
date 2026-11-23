package com.example.loginmonitoring.config;

import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import com.example.loginmonitoring.dto.RegistrationRequest;
import com.example.loginmonitoring.service.UserService;

/**
 * On startup, creates (or repairs) the administrator account from the ADMIN_EMAIL and
 * ADMIN_PASSWORD environment variables. There is no public way to become an admin.
 * Running it again is harmless: an existing, correct admin account is left unchanged.
 */
@Component
public class AdminInitializer implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AdminInitializer.class);
    private static final Pattern STRONG_PASSWORD = Pattern.compile(RegistrationRequest.PASSWORD_PATTERN);

    private final AdminProperties adminProperties;
    private final UserService userService;

    public AdminInitializer(AdminProperties adminProperties, UserService userService) {
        this.adminProperties = adminProperties;
        this.userService = userService;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!adminProperties.isConfigured()) {
            log.warn("ADMIN_EMAIL / ADMIN_PASSWORD are not set - no administrator account was created.");
            return;
        }
        String password = adminProperties.password();
        if (password.length() < RegistrationRequest.PASSWORD_MIN
                || password.length() > RegistrationRequest.PASSWORD_MAX
                || password.getBytes(StandardCharsets.UTF_8).length > 72   // BCrypt limit
                || !STRONG_PASSWORD.matcher(password).matches()) {
            log.error("ADMIN_PASSWORD must be 8-64 characters with at least one letter and one digit - "
                    + "administrator account was NOT created.");
            return;
        }

        String result = userService.createOrUpdateAdmin(adminProperties.name(), adminProperties.email(), password);
        log.info("Administrator account {} ({}).", result, UserService.normalizeEmail(adminProperties.email()));
    }
}

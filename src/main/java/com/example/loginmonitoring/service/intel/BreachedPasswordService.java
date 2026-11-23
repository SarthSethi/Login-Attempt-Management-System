package com.example.loginmonitoring.service.intel;

import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Locale;
import java.util.OptionalLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import com.example.loginmonitoring.config.IntegrationProperties;

/**
 * Checks whether a password appears in known data breaches, using the free
 * "Pwned Passwords" service of Have I Been Pwned.
 *
 * <p>The password never leaves the server: it is hashed with SHA-1 and only the first 5
 * characters of the hash are sent ("k-anonymity"). The service answers with every hash that
 * starts with those 5 characters, and the comparison happens here.
 */
@Service
public class BreachedPasswordService {

    private static final Logger log = LoggerFactory.getLogger(BreachedPasswordService.class);

    private final IntegrationProperties properties;
    private final RestClient restClient;

    public BreachedPasswordService(IntegrationProperties properties) {
        this.properties = properties;
        HttpClient httpClient = HttpClient.newBuilder().connectTimeout(properties.timeout()).build();
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(httpClient);
        factory.setReadTimeout(properties.timeout());
        this.restClient = RestClient.builder()
                .requestFactory(factory)
                .defaultHeader("User-Agent", "LAMS-login-monitor/2.0")
                .defaultHeader("Add-Padding", "true")
                .build();
    }

    /**
     * How many times the password was seen in breaches (0 = not found).
     * Empty if the check is switched off or the service could not be reached - in that case the
     * password is accepted, so an outage never stops people from registering.
     */
    public OptionalLong breachCount(String password) {
        if (!properties.breachCheckEnabled() || password == null || password.isEmpty()) {
            return OptionalLong.empty();
        }
        try {
            String hash = sha1Hex(password);
            String prefix = hash.substring(0, 5);
            String suffix = hash.substring(5);
            String body = restClient.get()
                    .uri(properties.breachCheckUrl().replace("{prefix}", prefix))
                    .retrieve()
                    .body(String.class);
            return OptionalLong.of(findCount(body, suffix));
        } catch (RuntimeException ex) {
            log.warn("Breached-password check unavailable: {}", ex.getMessage());
            return OptionalLong.empty();
        }
    }

    /** Reads lines of the form "HASH_SUFFIX:COUNT". Padding lines have a count of 0. */
    static long findCount(String body, String suffix) {
        if (body == null) {
            return 0;
        }
        for (String line : body.split("\\r?\\n")) {
            int colon = line.indexOf(':');
            if (colon > 0 && line.substring(0, colon).trim().equalsIgnoreCase(suffix)) {
                try {
                    return Long.parseLong(line.substring(colon + 1).trim());
                } catch (NumberFormatException ex) {
                    return 0;
                }
            }
        }
        return 0;
    }

    static String sha1Hex(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            byte[] bytes = digest.digest(password.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(bytes).toUpperCase(Locale.ROOT);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-1 not available", ex);
        }
    }
}

package com.example.loginmonitoring.service;

import java.time.Clock;
import java.time.LocalDateTime;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.example.loginmonitoring.config.IntegrationProperties;
import com.example.loginmonitoring.repository.LoginAttemptRepository;

/** Deletes old login attempts every night so the free database does not fill up. */
@Component
public class RetentionJob {

    private static final Logger log = LoggerFactory.getLogger(RetentionJob.class);

    private final LoginAttemptRepository repository;
    private final IntegrationProperties properties;
    private final Clock clock;

    public RetentionJob(LoginAttemptRepository repository, IntegrationProperties properties, Clock clock) {
        this.repository = repository;
        this.properties = properties;
        this.clock = clock;
    }

    @Scheduled(cron = "0 30 3 * * *", zone = "UTC")
    @Transactional
    public void deleteOldAttempts() {
        if (properties.retention().isZero() || properties.retention().isNegative()) {
            return;
        }
        int deleted = repository.deleteOlderThan(LocalDateTime.now(clock).minus(properties.retention()));
        if (deleted > 0) {
            log.info("Retention: deleted {} login attempts older than {}", deleted, properties.retention());
        }
    }
}

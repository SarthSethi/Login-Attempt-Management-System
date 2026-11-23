package com.example.loginmonitoring.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import com.example.loginmonitoring.entity.AttemptReason;
import com.example.loginmonitoring.entity.LoginOutcome;
import com.example.loginmonitoring.service.LoginProtectionService.Action;
import com.example.loginmonitoring.support.IntegrationTestBase;

class LoginAttemptServiceConcurrencyTest extends IntegrationTestBase {

    @Autowired
    private LoginProtectionService protectionService;

    @Test
    @DisplayName("Many simultaneous failures from one IP create exactly one block")
    void concurrentFailuresCreateSingleBlock() throws Exception {
        int threads = 20;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Boolean>> results = new ArrayList<>();

        for (int i = 0; i < threads; i++) {
            String email = "user" + i + "@example.com";
            results.add(pool.submit(() -> {
                start.await();
                return protectionService.onFailure(AttemptContext.real("192.0.2.50", email, null),
                        AttemptReason.UNKNOWN_EMAIL).action() == Action.IP_BLOCKED;
            }));
        }
        start.countDown();

        int blockedResponses = 0;
        for (Future<Boolean> result : results) {
            if (result.get(30, TimeUnit.SECONDS)) {
                blockedResponses++;
            }
        }
        pool.shutdown();

        assertThat(loginAttemptRepository.countByOutcome(LoginOutcome.FAILED)).isEqualTo(threads);
        assertThat(blockedIpRepository.count()).isEqualTo(1);
        // Rule 2 (4 different accounts): attempts 4..20 all report "blocked"
        assertThat(blockedResponses).isEqualTo(threads - 3);
    }
}

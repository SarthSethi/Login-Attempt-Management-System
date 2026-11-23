package com.example.loginmonitoring.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import com.example.loginmonitoring.entity.AccountLock;
import com.example.loginmonitoring.entity.AlertType;
import com.example.loginmonitoring.entity.AttemptReason;
import com.example.loginmonitoring.entity.BlockSource;
import com.example.loginmonitoring.entity.BlockedIp;
import com.example.loginmonitoring.entity.LockType;
import com.example.loginmonitoring.entity.LoginAttempt;
import com.example.loginmonitoring.entity.LoginOutcome;
import com.example.loginmonitoring.entity.Role;
import com.example.loginmonitoring.entity.SecurityAlert;
import com.example.loginmonitoring.service.BlockedIpService;
import com.example.loginmonitoring.service.CustomUserDetailsService;
import com.example.loginmonitoring.support.IntegrationTestBase;

/**
 * The layered detection rules, tested end-to-end through the real login form:
 * Rule 1 account+IP lock, Rule 2 credential stuffing, Rule 3 high volume,
 * Rule 4 distributed attack, Rule 5 repeat-offender escalation, and the allow-list.
 */
class LoginProtectionRulesTest extends IntegrationTestBase {

    private static final String ATTACKER_IP = "192.168.1.10";
    private static final String OTHER_IP = "192.168.1.20";
    private static final String WRONG = "WrongPass999";

    @Autowired
    private BlockedIpService blockedIpService;

    /** Spy on the real user lookup so we can prove credentials are NOT checked while blocked. */
    @MockitoSpyBean
    private CustomUserDetailsService userDetailsService;

    @BeforeEach
    void createUsers() {
        createUser("User One", "user1@gmail.com", PASSWORD, Role.USER);
        createUser("User Two", "user2@gmail.com", PASSWORD, Role.USER);
        createUser("User Three", "user3@gmail.com", PASSWORD, Role.USER);
        clearInvocations(userDetailsService);
    }

    private void failTimes(int times, String email, String ip) throws Exception {
        for (int i = 0; i < times; i++) {
            login(email, WRONG, ip);
        }
    }

    /** Rule 2 needs 4 different accounts; this blocks ATTACKER_IP. */
    private void credentialStuffing(String ip) throws Exception {
        login("user1@gmail.com", WRONG, ip);
        login("user2@gmail.com", WRONG, ip);
        login("user3@gmail.com", WRONG, ip);
        login("unknown@gmail.com", WRONG, ip);
    }

    // ---------------------------------------------------------------- Rule 1

    @Test
    @DisplayName("Rule 1: four failures do not lock anything and the real user can still log in")
    void fourFailuresDoNotLock() throws Exception {
        failTimes(4, "user1@gmail.com", ATTACKER_IP);

        assertThat(accountLockRepository.count()).isZero();
        assertThat(blockedIpRepository.count()).isZero();
        login("user1@gmail.com", PASSWORD, ATTACKER_IP)
                .andExpect(redirectedUrl("/dashboard"))
                .andExpect(authenticated());
    }

    @Test
    @DisplayName("Rule 1: the login page warns when only a few attempts are left")
    void attemptsLeftWarning() throws Exception {
        login("user1@gmail.com", WRONG, ATTACKER_IP).andExpect(redirectedUrl("/login?error"));
        login("user1@gmail.com", WRONG, ATTACKER_IP).andExpect(redirectedUrl("/login?error"));
        login("user1@gmail.com", WRONG, ATTACKER_IP).andExpect(redirectedUrl("/login?error"));
        login("user1@gmail.com", WRONG, ATTACKER_IP).andExpect(redirectedUrl("/login?error"));
    }

    @Test
    @DisplayName("Rule 1: the fifth failure locks that account for that IP for 15 minutes")
    void fifthFailureLocksAccountForThisIp() throws Exception {
        failTimes(4, "user1@gmail.com", ATTACKER_IP);

        login("user1@gmail.com", WRONG, ATTACKER_IP)
                .andExpect(redirectedUrl("/login?locked"))
                .andExpect(unauthenticated());

        AccountLock lock = accountLockRepository.findAll().get(0);
        LocalDateTime now = LocalDateTime.now(clock);
        assertThat(lock.getType()).isEqualTo(LockType.ACCOUNT_IP);
        assertThat(lock.getEmail()).isEqualTo("user1@gmail.com");
        assertThat(lock.getIpAddress()).isEqualTo(ATTACKER_IP);
        assertThat(lock.getExpiresAt()).isEqualTo(now.plusMinutes(15));
        assertThat(blockedIpRepository.count()).as("the IP itself is not blocked").isZero();
        assertThat(alertRepository.findAll()).extracting(SecurityAlert::getType).containsExactly(AlertType.BRUTE_FORCE);
    }

    @Test
    @DisplayName("Rule 1: a locked account is rejected from that IP without checking the password")
    void lockedPairRejectedWithoutPasswordCheck() throws Exception {
        failTimes(5, "user1@gmail.com", ATTACKER_IP);
        clearInvocations(userDetailsService);

        login("user1@gmail.com", PASSWORD, ATTACKER_IP)
                .andExpect(redirectedUrl("/login?locked"))
                .andExpect(unauthenticated());
        verify(userDetailsService, never()).loadUserByUsername(anyString());

        LoginAttempt rejected = loginAttemptRepository.findAll().stream()
                .filter(a -> a.getOutcome() == LoginOutcome.BLOCKED).findFirst().orElseThrow();
        assertThat(rejected.getReason()).isEqualTo(AttemptReason.ACCOUNT_IP_LOCKED);
    }

    @Test
    @DisplayName("Rule 1: shared Wi-Fi - other accounts on the same IP and the same account elsewhere still work")
    void sharedNetworkUnaffected() throws Exception {
        failTimes(5, "user1@gmail.com", ATTACKER_IP);

        login("user2@gmail.com", PASSWORD, ATTACKER_IP)
                .andExpect(redirectedUrl("/dashboard"))
                .andExpect(authenticated().withUsername("user2@gmail.com"));
        login("user1@gmail.com", PASSWORD, OTHER_IP)
                .andExpect(redirectedUrl("/dashboard"))
                .andExpect(authenticated().withUsername("user1@gmail.com"));
    }

    @Test
    @DisplayName("Rule 1: a successful login resets the counter for that account and IP")
    void successResetsPairCounter() throws Exception {
        failTimes(4, "user1@gmail.com", ATTACKER_IP);
        login("user1@gmail.com", PASSWORD, ATTACKER_IP).andExpect(redirectedUrl("/dashboard"));

        login("user1@gmail.com", WRONG, ATTACKER_IP).andExpect(redirectedUrl("/login?error"));
        assertThat(accountLockRepository.count()).isZero();
    }

    @Test
    @DisplayName("Rule 1: attempts older than 10 minutes do not count (rolling window)")
    void rollingWindow() throws Exception {
        failTimes(4, "user1@gmail.com", ATTACKER_IP);
        clock.advance(Duration.ofMinutes(10).plusSeconds(1));

        login("user1@gmail.com", WRONG, ATTACKER_IP).andExpect(redirectedUrl("/login?error"));
        assertThat(accountLockRepository.count()).isZero();
    }

    @Test
    @DisplayName("Rule 1: 5 failures spread over 8 minutes still lock; the lock ends after 15 minutes")
    void spreadFailuresLockThenExpire() throws Exception {
        for (int i = 0; i < 4; i++) {
            login("user1@gmail.com", WRONG, ATTACKER_IP);
            clock.advance(Duration.ofMinutes(2));
        }
        login("user1@gmail.com", WRONG, ATTACKER_IP).andExpect(redirectedUrl("/login?locked"));

        clock.advance(Duration.ofMinutes(14).plusSeconds(59));
        login("user1@gmail.com", PASSWORD, ATTACKER_IP).andExpect(redirectedUrl("/login?locked"));
        clock.advance(Duration.ofSeconds(1));
        login("user1@gmail.com", PASSWORD, ATTACKER_IP).andExpect(redirectedUrl("/dashboard"));
    }

    // ---------------------------------------------------------------- Rule 2

    @Test
    @DisplayName("Rule 2: four different accounts failing from one IP block the whole IP")
    void credentialStuffingBlocksIp() throws Exception {
        login("user1@gmail.com", WRONG, ATTACKER_IP).andExpect(redirectedUrl("/login?error"));
        login("user2@gmail.com", WRONG, ATTACKER_IP).andExpect(redirectedUrl("/login?error"));
        login("user3@gmail.com", WRONG, ATTACKER_IP).andExpect(redirectedUrl("/login?error"));
        // 4th account has no user at all - still counts
        login("unknown@gmail.com", WRONG, ATTACKER_IP).andExpect(redirectedUrl("/login?blocked"));

        List<LoginAttempt> attempts = loginAttemptRepository.findAll();
        assertThat(attempts).hasSize(4).allSatisfy(a -> assertThat(a.getOutcome()).isEqualTo(LoginOutcome.FAILED));
        assertThat(attempts).extracting(LoginAttempt::getReason).containsExactlyInAnyOrder(
                AttemptReason.WRONG_PASSWORD, AttemptReason.WRONG_PASSWORD, AttemptReason.WRONG_PASSWORD,
                AttemptReason.UNKNOWN_EMAIL);

        BlockedIp block = blockedIpRepository.findAll().get(0);
        assertThat(block.getIpAddress()).isEqualTo(ATTACKER_IP);
        assertThat(block.getExpiresAt()).isEqualTo(LocalDateTime.now(clock).plusMinutes(15));
        assertThat(block.getReason()).startsWith("Credential stuffing");
        assertThat(block.getLevel()).isEqualTo(1);
        assertThat(alertRepository.findAll()).extracting(SecurityAlert::getType)
                .containsExactly(AlertType.CREDENTIAL_STUFFING);
    }

    @Test
    @DisplayName("Correct credentials from a blocked IP are rejected without checking them")
    void correctCredentialsFromBlockedIpRejected() throws Exception {
        credentialStuffing(ATTACKER_IP);
        clearInvocations(userDetailsService);

        login("user2@gmail.com", PASSWORD, ATTACKER_IP)
                .andExpect(redirectedUrl("/login?blocked"))
                .andExpect(unauthenticated());
        verify(userDetailsService, never()).loadUserByUsername(anyString());
        assertThat(loginAttemptRepository.countByOutcome(LoginOutcome.SUCCESS)).isZero();
        assertThat(loginAttemptRepository.countByOutcome(LoginOutcome.BLOCKED)).isEqualTo(1);
    }

    @Test
    @DisplayName("Blocking one IP does not affect a different IP")
    void otherIpUnaffected() throws Exception {
        credentialStuffing(ATTACKER_IP);

        assertThat(blockedIpService.isBlocked(OTHER_IP)).isFalse();
        login("user1@gmail.com", PASSWORD, OTHER_IP)
                .andExpect(redirectedUrl("/dashboard"))
                .andExpect(authenticated().withUsername("user1@gmail.com"));
    }

    @Test
    @DisplayName("After 15 minutes the IP is unblocked automatically and the old block stays as history")
    void automaticUnblock() throws Exception {
        credentialStuffing(ATTACKER_IP);

        clock.advance(Duration.ofMinutes(14).plusSeconds(59));
        login("user1@gmail.com", PASSWORD, ATTACKER_IP).andExpect(redirectedUrl("/login?blocked"));

        clock.advance(Duration.ofSeconds(1));
        login("user1@gmail.com", PASSWORD, ATTACKER_IP)
                .andExpect(redirectedUrl("/dashboard"))
                .andExpect(authenticated());
        assertThat(blockedIpRepository.count()).isEqualTo(1);
    }

    @Test
    @DisplayName("Requests from a blocked IP are logged as BLOCKED and do not extend the block")
    void blockedAttemptLoggingDoesNotExtendBlock() throws Exception {
        credentialStuffing(ATTACKER_IP);
        LocalDateTime originalExpiry = blockedIpRepository.findAll().get(0).getExpiresAt();

        clock.advance(Duration.ofMinutes(5));
        login("user1@gmail.com", WRONG, ATTACKER_IP).andExpect(redirectedUrl("/login?blocked"));
        clock.advance(Duration.ofMinutes(5));
        login("user3@gmail.com", PASSWORD, ATTACKER_IP).andExpect(redirectedUrl("/login?blocked"));

        assertThat(loginAttemptRepository.countByOutcome(LoginOutcome.BLOCKED)).isEqualTo(2);
        assertThat(blockedIpRepository.findAll()).singleElement()
                .satisfies(b -> assertThat(b.getExpiresAt()).isEqualTo(originalExpiry));

        clock.advance(Duration.ofMinutes(5));
        login("user1@gmail.com", PASSWORD, ATTACKER_IP).andExpect(redirectedUrl("/dashboard"));
    }

    // ---------------------------------------------------------------- Rule 3

    @Test
    @DisplayName("Rule 3: ten failures from one IP (three accounts) block the IP")
    void highVolumeBlocksIp() throws Exception {
        failTimes(4, "user1@gmail.com", ATTACKER_IP);
        failTimes(4, "user2@gmail.com", ATTACKER_IP);
        login("user3@gmail.com", WRONG, ATTACKER_IP).andExpect(redirectedUrl("/login?error"));
        assertThat(blockedIpService.isBlocked(ATTACKER_IP)).isFalse();

        login("user3@gmail.com", WRONG, ATTACKER_IP).andExpect(redirectedUrl("/login?blocked"));
        assertThat(blockedIpRepository.findAll().get(0).getReason()).startsWith("Too many failed attempts: 10");
        assertThat(alertRepository.findAll()).extracting(SecurityAlert::getType).contains(AlertType.HIGH_VOLUME);
    }

    // ---------------------------------------------------------------- Rule 4

    @Test
    @DisplayName("Rule 4: a distributed attack locks the account for new IPs; the owner's known IP still works")
    void distributedAttackLocksAccountForNewIps() throws Exception {
        String ownerIp = "10.1.1.1";
        login("user1@gmail.com", PASSWORD, ownerIp).andExpect(redirectedUrl("/dashboard"));

        String[] botnet = {"10.2.0.1", "10.2.0.2", "10.2.0.3", "10.2.0.4"};
        for (int i = 0; i < 7; i++) {
            login("user1@gmail.com", WRONG, botnet[i % 4]).andExpect(redirectedUrl("/login?error"));
        }
        // 8th failure from the 4th IP -> account locked for unknown IPs
        login("user1@gmail.com", WRONG, botnet[3]).andExpect(redirectedUrl("/login?locked"));

        AccountLock lock = accountLockRepository.findAll().stream()
                .filter(l -> l.getType() == LockType.ACCOUNT).findFirst().orElseThrow();
        assertThat(lock.getEmail()).isEqualTo("user1@gmail.com");
        assertThat(lock.getIpAddress()).isNull();
        assertThat(alertRepository.findAll()).extracting(SecurityAlert::getType).contains(AlertType.DISTRIBUTED_ATTACK);

        // A brand-new IP is stopped even with the right password ...
        login("user1@gmail.com", PASSWORD, "10.3.3.3").andExpect(redirectedUrl("/login?locked"));
        // ... but the owner's usual IP works, and other accounts are not affected
        login("user1@gmail.com", PASSWORD, ownerIp).andExpect(redirectedUrl("/dashboard"));
        login("user2@gmail.com", PASSWORD, "10.3.3.3").andExpect(redirectedUrl("/dashboard"));
    }

    // ---------------------------------------------------------------- Rule 5

    @Test
    @DisplayName("Rule 5: a repeat offender's second block lasts 1 hour, the third 24 hours")
    void repeatOffenderEscalation() throws Exception {
        credentialStuffing(ATTACKER_IP);
        clock.advance(Duration.ofMinutes(15));

        // Old failures are not counted again: one new failure does not re-block
        login("user1@gmail.com", WRONG, ATTACKER_IP).andExpect(redirectedUrl("/login?error"));
        login("user2@gmail.com", WRONG, ATTACKER_IP);
        login("user3@gmail.com", WRONG, ATTACKER_IP);
        login("unknown@gmail.com", WRONG, ATTACKER_IP).andExpect(redirectedUrl("/login?blocked"));

        BlockedIp second = blockedIpRepository.findAll().stream().filter(b -> b.getLevel() == 2).findFirst().orElseThrow();
        assertThat(second.getExpiresAt()).isEqualTo(LocalDateTime.now(clock).plusHours(1));

        clock.advance(Duration.ofHours(1));
        credentialStuffing(ATTACKER_IP);
        BlockedIp third = blockedIpRepository.findAll().stream().filter(b -> b.getLevel() == 3).findFirst().orElseThrow();
        assertThat(third.getExpiresAt()).isEqualTo(LocalDateTime.now(clock).plusHours(24));
    }

    // ---------------------------------------------------------------- allow-list and manual blocks

    @Test
    @DisplayName("Trusted (allow-listed) IPs are never IP-blocked, but account protection still applies")
    void allowlistedIpNotBlocked() throws Exception {
        allowlistService.add("192.168.1.0/24", "College Wi-Fi", "admin@example.com");

        credentialStuffing(ATTACKER_IP);
        assertThat(blockedIpService.isBlocked(ATTACKER_IP)).isFalse();

        failTimes(4, "user2@gmail.com", ATTACKER_IP); // 5 failures for user2 in total
        login("user2@gmail.com", PASSWORD, ATTACKER_IP).andExpect(redirectedUrl("/login?locked"));
    }

    @Test
    @DisplayName("A permanent ban shows the 'blocked by the administrator' message")
    void permanentBan() throws Exception {
        blockedIpService.blockManually(ATTACKER_IP, null, "Manual: test", BlockSource.MANUAL, "admin@example.com", false);

        login("user1@gmail.com", PASSWORD, ATTACKER_IP).andExpect(redirectedUrl("/login?banned"));
        assertThat(blockedIpService.isBlocked(ATTACKER_IP)).isTrue();

        clock.advance(Duration.ofDays(365));
        assertThat(blockedIpService.isBlocked(ATTACKER_IP)).isTrue();
    }
}

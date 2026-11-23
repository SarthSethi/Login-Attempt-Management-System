package com.example.loginmonitoring.service;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Limit;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.loginmonitoring.entity.AttemptReason;
import com.example.loginmonitoring.entity.LoginAttempt;
import com.example.loginmonitoring.entity.LoginOutcome;
import com.example.loginmonitoring.entity.RiskFlag;
import com.example.loginmonitoring.repository.LoginAttemptRepository;
import com.example.loginmonitoring.service.intel.DeviceInfo;
import com.example.loginmonitoring.service.intel.UserAgentParser;

/**
 * Saves login attempts and answers questions about them. The detection rules that decide
 * what happens after a failure live in {@link LoginProtectionService}.
 */
@Service
public class LoginAttemptService {

    private final LoginAttemptRepository loginAttemptRepository;
    private final Clock clock;

    public LoginAttemptService(LoginAttemptRepository loginAttemptRepository, Clock clock) {
        this.loginAttemptRepository = loginAttemptRepository;
        this.clock = clock;
    }

    /** Saves one attempt together with the device read from the User-Agent. */
    @Transactional
    public LoginAttempt record(AttemptContext context, LoginOutcome outcome, AttemptReason reason,
                               Collection<RiskFlag> riskFlags) {
        LoginAttempt attempt = new LoginAttempt(context.ip(), context.email(), outcome, now());
        attempt.setReason(reason);
        String userAgent = context.userAgent();
        if (userAgent != null && userAgent.length() > LoginAttempt.MAX_USER_AGENT_LENGTH) {
            userAgent = userAgent.substring(0, LoginAttempt.MAX_USER_AGENT_LENGTH);
        }
        attempt.setUserAgent(userAgent);
        DeviceInfo device = UserAgentParser.parse(context.userAgent());
        attempt.setBrowser(device.browser());
        attempt.setOs(device.os());
        attempt.setDeviceType(device.deviceType());
        if (outcome == LoginOutcome.SUCCESS) {
            attempt.setRisk(riskFlags);
        }
        attempt.setSimulated(context.simulated());
        return loginAttemptRepository.save(attempt);
    }

    /** The successful login before the current one, if there was one. */
    @Transactional(readOnly = true)
    public Optional<LoginAttempt> findPreviousSuccessfulLogin(String email) {
        List<LoginAttempt> lastTwo = loginAttemptRepository
                .findTop2ByAttemptedEmailAndOutcomeOrderByAttemptedAtDescIdDesc(cleanEmail(email), LoginOutcome.SUCCESS);
        return lastTwo.size() < 2 ? Optional.empty() : Optional.of(lastTwo.get(1));
    }

    /** The successful login before the one that started the current session. */
    @Transactional(readOnly = true)
    public Optional<LoginAttempt> findSuccessfulLoginBefore(String email, long loginAttemptId) {
        return loginAttemptRepository.findFirstByAttemptedEmailAndOutcomeAndIdLessThanOrderByIdDesc(
                cleanEmail(email), LoginOutcome.SUCCESS, loginAttemptId);
    }

    /** FAILED attempts from this IP inside the rolling window (any email). */
    @Transactional(readOnly = true)
    public long countFailuresFromIpSince(String ipAddress, LocalDateTime after) {
        return loginAttemptRepository.countByIpAddressAndOutcomeAndAttemptedAtAfter(ipAddress, LoginOutcome.FAILED, after);
    }

    // ---------- user activity ----------

    @Transactional(readOnly = true)
    public List<LoginAttempt> activityFor(String email, int max) {
        return loginAttemptRepository.findByAttemptedEmailOrderByAttemptedAtDescIdDesc(cleanEmail(email), Limit.of(max));
    }

    @Transactional(readOnly = true)
    public long countUnsuccessfulSince(String email, LocalDateTime after) {
        return loginAttemptRepository.countUnsuccessfulForEmailAfter(cleanEmail(email), after);
    }

    @Transactional(readOnly = true)
    public Optional<LoginAttempt> findById(long id) {
        return loginAttemptRepository.findById(id);
    }

    @Transactional
    public void markReported(long id) {
        loginAttemptRepository.findById(id).ifPresent(attempt -> attempt.setReported(true));
    }

    // ---------- admin queries ----------

    @Transactional(readOnly = true)
    public long countAll() {
        return loginAttemptRepository.count();
    }

    @Transactional(readOnly = true)
    public long countByOutcome(LoginOutcome outcome) {
        return loginAttemptRepository.countByOutcome(outcome);
    }

    /** Newest attempts first. All filters are optional (null = no filter). Page numbers start at 0. */
    @Transactional(readOnly = true)
    public Page<LoginAttempt> search(LoginOutcome outcome, String ipSearch, String emailSearch, int page, int size) {
        return loginAttemptRepository.search(outcome, ipSearch, emailSearch, PageRequest.of(page, size));
    }

    @Transactional(readOnly = true)
    public List<LoginAttempt> latest(int max) {
        return loginAttemptRepository.findAllByOrderByIdDesc(Limit.of(max));
    }

    @Transactional(readOnly = true)
    public List<LoginAttempt> newerThan(long id, int max) {
        return loginAttemptRepository.findByIdGreaterThanOrderByIdDesc(id, Limit.of(max));
    }

    // ---------- helpers ----------

    /** Lower-case, trimmed and cut to the column length. Blank becomes null. */
    public static String cleanEmail(String email) {
        String normalized = UserService.normalizeEmail(email);
        if (normalized == null || normalized.isEmpty()) {
            return null;
        }
        return normalized.length() > LoginAttempt.MAX_EMAIL_LENGTH
                ? normalized.substring(0, LoginAttempt.MAX_EMAIL_LENGTH)
                : normalized;
    }

    private LocalDateTime now() {
        return LocalDateTime.now(clock);
    }
}

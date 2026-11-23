package com.example.loginmonitoring.service;

import java.time.Clock;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import com.example.loginmonitoring.config.LoginSecurityProperties;
import com.example.loginmonitoring.entity.AccountLock;
import com.example.loginmonitoring.entity.AlertSeverity;
import com.example.loginmonitoring.entity.AlertType;
import com.example.loginmonitoring.entity.AttemptReason;
import com.example.loginmonitoring.entity.BlockedIp;
import com.example.loginmonitoring.entity.IpInfo;
import com.example.loginmonitoring.entity.IpInfoStatus;
import com.example.loginmonitoring.entity.LockType;
import com.example.loginmonitoring.entity.LoginAttempt;
import com.example.loginmonitoring.entity.LoginOutcome;
import com.example.loginmonitoring.entity.RiskFlag;
import com.example.loginmonitoring.repository.LoginAttemptRepository;
import com.example.loginmonitoring.service.intel.DeviceInfo;
import com.example.loginmonitoring.service.intel.IpIntelService;
import com.example.loginmonitoring.service.intel.UserAgentParser;

/**
 * The detection rules. Every login attempt goes through this class.
 *
 * <pre>
 *  BEFORE the password is checked  (checkBeforeLogin)
 *    - IP blocked?                                    -> reject, password not checked
 *    - this account locked for this IP?              -> reject
 *    - this account under attack and IP is new?      -> reject (owner's usual IPs still work)
 *
 *  AFTER a wrong password  (onFailure)
 *    Rule 1  5 failures, same account + same IP, 10 min   -> lock that account for that IP only
 *    Rule 2  4 different accounts failing from one IP     -> block the IP  (credential stuffing)
 *    Rule 3  10 failures from one IP, any accounts        -> block the IP  (high volume)
 *    Rule 4  8 failures on one account from 3+ IPs        -> lock the account for new IPs
 *    Rule 5  repeat offenders get longer blocks: 15 min -> 1 h -> 24 h
 *    Allow-listed IPs are never blocked by rules 2, 3 and 5.
 *
 *  AFTER a correct password  (onSuccess)
 *    - risk flags: after failed attempts, new country, new device, VPN / data centre, script
 *    - risky logins raise an alert for the administrator
 * </pre>
 * The numbers come from {@link LoginSecurityProperties}.
 */
@Service
public class LoginProtectionService {

    private static final Logger log = LoggerFactory.getLogger(LoginProtectionService.class);

    /** What happened to the login after a failure. Later values are "stronger". */
    public enum Action { NONE, ACCOUNT_IP_LOCKED, ACCOUNT_LOCKED, IP_BLOCKED }

    /** Why a login was rejected before the password was checked, and until when. */
    public record Denial(AttemptReason reason, LocalDateTime until, boolean permanent) {
        public long minutesLeft(LocalDateTime now) {
            long seconds = Math.max(0, Duration.between(now, until).toSeconds());
            return Math.max(1, (seconds + 59) / 60);
        }
    }

    /**
     * Result of a failed attempt.
     *
     * @param attemptsLeft failures left before Rule 1 locks this account for this IP (-1 if locked)
     */
    public record FailureResult(Action action, LocalDateTime until, int attemptsLeft) {
    }

    private final LoginAttemptService attemptService;
    private final LoginAttemptRepository attemptRepository;
    private final BlockedIpService blockedIpService;
    private final AccountLockService accountLockService;
    private final AllowlistService allowlistService;
    private final AlertService alertService;
    private final IpIntelService ipIntelService;
    private final LoginSecurityProperties properties;
    private final Clock clock;
    private final TransactionTemplate transactionTemplate;

    /**
     * Failed attempts are processed one at a time so that two parallel requests can never both
     * miss the limit (or both create a block). This works because the app runs as one instance.
     */
    private final ReentrantLock failureLock = new ReentrantLock();

    public LoginProtectionService(LoginAttemptService attemptService, LoginAttemptRepository attemptRepository,
                                  BlockedIpService blockedIpService, AccountLockService accountLockService,
                                  AllowlistService allowlistService, AlertService alertService,
                                  IpIntelService ipIntelService, LoginSecurityProperties properties, Clock clock,
                                  PlatformTransactionManager transactionManager) {
        this.attemptService = attemptService;
        this.attemptRepository = attemptRepository;
        this.blockedIpService = blockedIpService;
        this.accountLockService = accountLockService;
        this.allowlistService = allowlistService;
        this.alertService = alertService;
        this.ipIntelService = ipIntelService;
        this.properties = properties;
        this.clock = clock;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
        log.info("Login protection: account+IP lock after {} failures / {}; IP block after {} accounts or {} failures; "
                        + "account lock after {} failures from {}+ IPs; first block {}, repeat blocks {}",
                properties.maxFailedAttempts(), properties.monitoringWindow(), properties.ipMaxAccounts(),
                properties.ipMaxFailures(), properties.accountMaxFailures(), properties.accountMinIps(),
                properties.blockDuration(), properties.repeatBlockDurations());
    }

    // =====================================================================
    //  Before the password is checked
    // =====================================================================

    @Transactional(readOnly = true)
    public Optional<Denial> checkBeforeLogin(String ip, String email) {
        Optional<BlockedIp> block = blockedIpService.findActiveBlock(ip);
        if (block.isPresent()) {
            return Optional.of(new Denial(AttemptReason.IP_BLOCKED, block.get().getExpiresAt(), block.get().isPermanent()));
        }
        if (email == null) {
            return Optional.empty();
        }
        LocalDateTime now = now();
        for (AccountLock lock : accountLockService.activeLocks(email)) {
            if (lock.getType() == LockType.ACCOUNT_IP && ip.equals(lock.getIpAddress())) {
                return Optional.of(new Denial(AttemptReason.ACCOUNT_IP_LOCKED, lock.getExpiresAt(), false));
            }
        }
        for (AccountLock lock : accountLockService.activeLocks(email)) {
            if (lock.getType() == LockType.ACCOUNT && !isKnownIp(email, ip, now) && !allowlistService.isAllowlisted(ip)) {
                return Optional.of(new Denial(AttemptReason.ACCOUNT_LOCKED, lock.getExpiresAt(), false));
            }
        }
        return Optional.empty();
    }

    /** Saves a request that was rejected before its password was checked. Does not change any block. */
    public LoginAttempt recordDenied(AttemptContext context, Denial denial) {
        return attemptService.record(context, LoginOutcome.BLOCKED, denial.reason(), null);
    }

    // =====================================================================
    //  After a wrong password
    // =====================================================================

    public FailureResult onFailure(AttemptContext context, AttemptReason reason) {
        failureLock.lock();
        try {
            return transactionTemplate.execute(status -> applyRules(context, reason));
        } finally {
            failureLock.unlock();
        }
    }

    private FailureResult applyRules(AttemptContext ctx, AttemptReason reason) {
        attemptService.record(ctx, LoginOutcome.FAILED, reason, null);

        String ip = ctx.ip();
        String email = ctx.email();
        LocalDateTime now = now();
        LocalDateTime windowStart = now.minus(properties.monitoringWindow());
        String window = describe(properties.monitoringWindow());

        Action action = Action.NONE;
        LocalDateTime until = null;
        int attemptsLeft = -1;

        // ---- Rule 1: same account + same IP --------------------------------
        if (email != null) {
            Optional<AccountLock> lastPairLock = accountLockService.latestPairLock(email, ip);
            if (lastPairLock.isPresent() && lastPairLock.get().isActiveAt(now)) {
                action = Action.ACCOUNT_IP_LOCKED;
                until = lastPairLock.get().getExpiresAt();
            } else {
                long pairFailures = countPairFailures(email, ip, now, lastPairLock);
                if (pairFailures >= properties.maxFailedAttempts()) {
                    AccountLock lock = accountLockService.lockPair(email, ip,
                            pairFailures + " failed attempts in " + window + " from " + ip, ctx.simulated());
                    alertService.raise(AlertType.BRUTE_FORCE, AlertSeverity.MEDIUM, ip, email,
                            "Password guessing on " + email + " from " + ip + ": " + pairFailures
                                    + " failures in " + window + ". Locked for this IP for "
                                    + describe(properties.blockDuration()) + ".", ctx.simulated());
                    action = Action.ACCOUNT_IP_LOCKED;
                    until = lock.getExpiresAt();
                } else {
                    attemptsLeft = (int) (properties.maxFailedAttempts() - pairFailures);
                }
            }
        }

        // ---- Rules 2 + 3: the IP across all accounts ------------------------
        Optional<BlockedIp> activeBlock = blockedIpService.findActiveBlock(ip);
        if (activeBlock.isPresent()) {
            action = Action.IP_BLOCKED; // blocked by a parallel request a moment ago
            until = activeBlock.get().getExpiresAt();
        } else if (!allowlistService.isAllowlisted(ip)) {
            LocalDateTime from = ipCountFrom(ip, now);
            long accounts = attemptRepository.countDistinctEmailsFromIp(ip, LoginOutcome.FAILED, from);
            long failures = attemptRepository.countByIpAddressAndOutcomeAndAttemptedAtAfter(ip, LoginOutcome.FAILED, from);

            String why = null;
            AlertType type = null;
            if (accounts >= properties.ipMaxAccounts()) {
                why = "Credential stuffing: " + accounts + " different accounts tried in " + window;
                type = AlertType.CREDENTIAL_STUFFING;
            } else if (failures >= properties.ipMaxFailures()) {
                why = "Too many failed attempts: " + failures + " in " + window;
                type = AlertType.HIGH_VOLUME;
            }
            if (why != null) {
                BlockedIp block = blockedIpService.blockAutomatically(ip, why, ctx.simulated());
                String repeat = block.getLevel() > 1 ? " Repeat offender (block #" + block.getLevel() + " in 24 h)." : "";
                alertService.raise(type, block.getLevel() > 1 ? AlertSeverity.CRITICAL : AlertSeverity.HIGH, ip, null,
                        why + ". IP " + ip + " blocked for "
                                + describe(Duration.between(block.getBlockedAt(), block.getExpiresAt())) + "." + repeat,
                        ctx.simulated());
                action = Action.IP_BLOCKED;
                until = block.getExpiresAt();
            }
        }

        // ---- Rule 4: one account from many IPs ------------------------------
        if (email != null) {
            Optional<AccountLock> lastAccountLock = accountLockService.latestAccountLock(email);
            boolean alreadyLocked = lastAccountLock.isPresent() && lastAccountLock.get().isActiveAt(now);
            if (!alreadyLocked) {
                LocalDateTime from = latest(windowStart, lastAccountLock.map(AccountLock::getLockedAt).orElse(null), null);
                long failures = attemptRepository.countByAttemptedEmailAndOutcomeAndAttemptedAtAfter(
                        email, LoginOutcome.FAILED, from);
                long ips = attemptRepository.countDistinctIpsForEmail(email, LoginOutcome.FAILED, from);
                if (failures >= properties.accountMaxFailures() && ips >= properties.accountMinIps()) {
                    AccountLock lock = accountLockService.lockAccount(email,
                            failures + " failures from " + ips + " different IPs in " + window, ctx.simulated());
                    alertService.raise(AlertType.DISTRIBUTED_ATTACK, AlertSeverity.HIGH, null, email,
                            "Distributed attack on " + email + ": " + failures + " failures from " + ips
                                    + " different IPs in " + window + ". Sign-in from new locations paused for "
                                    + describe(properties.blockDuration()) + ".", ctx.simulated());
                    if (action.compareTo(Action.ACCOUNT_LOCKED) < 0 && !isKnownIp(email, ip, now)) {
                        action = Action.ACCOUNT_LOCKED;
                        until = lock.getExpiresAt();
                    }
                }
            }
        }

        return new FailureResult(action, until, action == Action.NONE ? attemptsLeft : -1);
    }

    // =====================================================================
    //  After a correct password
    // =====================================================================

    /** Saves the successful login with its risk flags and raises an alert when it looks risky. */
    public LoginAttempt onSuccess(AttemptContext ctx) {
        IpInfo ipInfo = ipIntelService.lookupNow(ctx.ip()); // outside the transaction: may call the network
        return transactionTemplate.execute(status -> recordSuccess(ctx, ipInfo));
    }

    private LoginAttempt recordSuccess(AttemptContext ctx, IpInfo ipInfo) {
        LocalDateTime now = now();
        String email = ctx.email();
        DeviceInfo device = UserAgentParser.parse(ctx.userAgent());
        Set<RiskFlag> flags = EnumSet.noneOf(RiskFlag.class);

        List<LoginAttempt> previous = attemptRepository
                .findByAttemptedEmailAndOutcomeAndAttemptedAtAfterOrderByAttemptedAtDescIdDesc(
                        email, LoginOutcome.SUCCESS, now.minus(properties.knownIpPeriod()), Limit.of(50));

        // Failures on this account since its last successful login (max. 1 hour back)
        LocalDateTime failuresFrom = latest(now.minusHours(1),
                previous.isEmpty() ? null : previous.get(0).getAttemptedAt(), null);
        long recentFailures = attemptRepository.countByAttemptedEmailAndOutcomeAndAttemptedAtAfter(
                email, LoginOutcome.FAILED, failuresFrom);
        if (recentFailures >= 3) {
            flags.add(RiskFlag.AFTER_FAILURES);
        }

        if (!previous.isEmpty()) {
            List<LoginAttempt> withDevice = previous.stream().filter(p -> p.getBrowser() != null).toList();
            boolean seenDevice = withDevice.stream().anyMatch(p -> p.getBrowser().equals(device.browser())
                    && java.util.Objects.equals(p.getOs(), device.os()));
            if (!withDevice.isEmpty() && !seenDevice) {
                flags.add(RiskFlag.NEW_DEVICE);
            }

            String country = knownCountry(ipInfo);
            if (country != null) {
                Map<String, IpInfo> earlier = ipIntelService.describeAll(
                        previous.stream().map(LoginAttempt::getIpAddress).distinct().toList());
                Set<String> countries = earlier.values().stream().map(LoginProtectionService::knownCountry)
                        .filter(java.util.Objects::nonNull).collect(Collectors.toSet());
                if (!countries.isEmpty() && !countries.contains(country)) {
                    flags.add(RiskFlag.NEW_COUNTRY);
                }
            }
        }
        if (ipInfo.isVpnOrHosting()) {
            flags.add(RiskFlag.VPN_OR_HOSTING);
        }
        if (device.automated()) {
            flags.add(RiskFlag.AUTOMATED_CLIENT);
        }

        LoginAttempt attempt = attemptService.record(ctx, LoginOutcome.SUCCESS, null, flags);

        int score = flags.stream().mapToInt(RiskFlag::getScore).sum();
        if (score >= 2) {
            AlertSeverity severity = score >= 5 ? AlertSeverity.CRITICAL : score >= 3 ? AlertSeverity.HIGH : AlertSeverity.MEDIUM;
            String reasons = flags.stream().map(RiskFlag::getLabel).collect(Collectors.joining(", "));
            String extra = flags.contains(RiskFlag.AFTER_FAILURES) ? " (" + recentFailures + " failed attempts before it)" : "";
            alertService.raise(AlertType.SUSPICIOUS_LOGIN, severity, ctx.ip(), email,
                    "Risky successful login to " + email + " from " + ctx.ip() + " (" + ipInfo.getLocationLabel()
                            + ", " + device.browser() + "): " + reasons + extra + ".", ctx.simulated());
        }
        return attempt;
    }

    // =====================================================================
    //  Live status for the login page
    // =====================================================================

    /** What the login page should tell this visitor right now (read from the database, so a refresh shows the same). */
    @Transactional(readOnly = true)
    public LoginStatus statusFor(String ip, String email) {
        LocalDateTime now = now();
        int accountLimit = properties.maxFailedAttempts();
        Optional<BlockedIp> block = blockedIpService.findActiveBlock(ip);
        if (block.isPresent()) {
            LoginStatus.State state = block.get().isPermanent() ? LoginStatus.State.IP_BANNED : LoginStatus.State.IP_BLOCKED;
            return LoginStatus.of(state, email, secondsUntil(block.get().getExpiresAt(), now), accountLimit);
        }
        if (email != null) {
            for (AccountLock lock : accountLockService.activeLocks(email)) {
                if (lock.getType() == LockType.ACCOUNT_IP && ip.equals(lock.getIpAddress())) {
                    return LoginStatus.of(LoginStatus.State.ACCOUNT_LOCKED, email,
                            secondsUntil(lock.getExpiresAt(), now), accountLimit);
                }
                if (lock.getType() == LockType.ACCOUNT && !isKnownIp(email, ip, now) && !allowlistService.isAllowlisted(ip)) {
                    return LoginStatus.of(LoginStatus.State.ACCOUNT_UNDER_ATTACK, email,
                            secondsUntil(lock.getExpiresAt(), now), accountLimit);
                }
            }
        }

        int accountFailures = email == null ? 0
                : (int) countPairFailures(email, ip, now, accountLockService.latestPairLock(email, ip));
        LocalDateTime ipFrom = ipCountFrom(ip, now);
        int ipFailures = (int) attemptRepository.countByIpAddressAndOutcomeAndAttemptedAtAfter(ip, LoginOutcome.FAILED, ipFrom);
        int ipAccounts = (int) attemptRepository.countDistinctEmailsFromIp(ip, LoginOutcome.FAILED, ipFrom);
        boolean ipWarning = !allowlistService.isAllowlisted(ip) && ipFailures > 0
                && (ipFailures >= properties.ipMaxFailures() - 3 || ipAccounts >= properties.ipMaxAccounts() - 1);
        LoginStatus.State state = accountFailures > 0 ? LoginStatus.State.FAILURES : LoginStatus.State.CLEAR;
        return new LoginStatus(state, email, 0, accountFailures, accountLimit, ipFailures, properties.ipMaxFailures(),
                ipAccounts, properties.ipMaxAccounts(), ipWarning);
    }

    /** Rule 1 counter: failures for this account from this IP since the window start, the last lock or the last success. */
    private long countPairFailures(String email, String ip, LocalDateTime now, Optional<AccountLock> lastPairLock) {
        LocalDateTime from = latest(now.minus(properties.monitoringWindow()),
                lastPairLock.map(AccountLock::getLockedAt).orElse(null),
                attemptRepository.findFirstByAttemptedEmailAndIpAddressAndOutcomeOrderByAttemptedAtDescIdDesc(
                        email, ip, LoginOutcome.SUCCESS).map(LoginAttempt::getAttemptedAt).orElse(null));
        return attemptRepository.countByIpAddressAndAttemptedEmailAndOutcomeAndAttemptedAtAfter(
                ip, email, LoginOutcome.FAILED, from);
    }

    /** Rules 2 and 3 count from the window start, or from the IP's last block (so old failures are not counted twice). */
    private LocalDateTime ipCountFrom(String ip, LocalDateTime now) {
        return latest(now.minus(properties.monitoringWindow()),
                blockedIpService.findLatestBlock(ip).map(BlockedIp::getBlockedAt).orElse(null), null);
    }

    private static long secondsUntil(LocalDateTime until, LocalDateTime now) {
        return Math.max(0, Duration.between(now, until).toSeconds());
    }

    // =====================================================================
    //  Helpers
    // =====================================================================

    /** True if the owner of this account logged in from this IP recently (90 days by default). */
    @Transactional(readOnly = true)
    public boolean isKnownIp(String email, String ip, LocalDateTime now) {
        return attemptRepository.existsByAttemptedEmailAndIpAddressAndOutcomeAndAttemptedAtAfter(
                email, ip, LoginOutcome.SUCCESS, now.minus(properties.knownIpPeriod()));
    }

    private static String knownCountry(IpInfo info) {
        if (info == null || info.getCountryCode() == null) {
            return null;
        }
        return info.getStatus() == IpInfoStatus.OK || info.getStatus() == IpInfoStatus.SIMULATED
                ? info.getCountryCode() : null;
    }

    private static LocalDateTime latest(LocalDateTime a, LocalDateTime b, LocalDateTime c) {
        LocalDateTime result = a;
        if (b != null && b.isAfter(result)) {
            result = b;
        }
        if (c != null && c.isAfter(result)) {
            result = c;
        }
        return result;
    }

    /** "10 min", "1 h", "24 h". */
    public static String describe(Duration duration) {
        long minutes = duration.toMinutes();
        if (minutes >= 60 && minutes % 60 == 0) {
            return (minutes / 60) + " h";
        }
        if (minutes >= 1) {
            return minutes + " min";
        }
        return duration.toSeconds() + " s";
    }

    private LocalDateTime now() {
        return LocalDateTime.now(clock);
    }
}

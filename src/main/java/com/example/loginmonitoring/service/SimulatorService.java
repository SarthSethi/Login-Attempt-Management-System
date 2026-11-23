package com.example.loginmonitoring.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.loginmonitoring.entity.AttemptReason;
import com.example.loginmonitoring.entity.LockType;
import com.example.loginmonitoring.entity.LoginAttempt;
import com.example.loginmonitoring.repository.AccountLockRepository;
import com.example.loginmonitoring.repository.BlockedIpRepository;
import com.example.loginmonitoring.repository.IpInfoRepository;
import com.example.loginmonitoring.repository.LoginAttemptRepository;
import com.example.loginmonitoring.repository.SecurityAlertRepository;
import com.example.loginmonitoring.repository.UserRepository;
import com.example.loginmonitoring.service.LoginProtectionService.Denial;
import com.example.loginmonitoring.service.LoginProtectionService.FailureResult;
import com.example.loginmonitoring.service.intel.IpIntelService;

/**
 * Attack simulator for demonstrations. It sends made-up login attempts through exactly the same
 * detection code as real logins, so the dashboard reacts the way it would to a real attack.
 *
 * <p>All simulated data is clearly marked: attempts, blocks, locks and alerts carry a
 * "simulated" flag, and the attacker IPs come from the documentation ranges 192.0.2.0/24,
 * 198.51.100.0/24 and 203.0.113.0/24, which never belong to a real computer. Their countries are
 * made up too. "Clear simulated data" removes all of it.
 */
@Service
public class SimulatorService {

    public enum Scenario {
        BRUTE_FORCE("Brute force",
                "One IP guesses passwords for one account.",
                "Expected: Rule 1 locks the account for that IP after 5 failures."),
        CREDENTIAL_STUFFING("Credential stuffing",
                "One IP tries leaked passwords on many accounts.",
                "Expected: Rule 2 blocks the IP after 4 different accounts."),
        DISTRIBUTED("Distributed attack",
                "Five IPs take turns guessing one account.",
                "Expected: Rule 4 locks the account for new IPs. The owner's usual IP still works."),
        ACCOUNT_TAKEOVER("Account takeover",
                "An attacker on a VPN fails 3 times, then guesses the right password.",
                "Expected: the login succeeds but is flagged and raises a critical alert.");

        private final String title;
        private final String description;
        private final String expected;

        Scenario(String title, String description, String expected) {
            this.title = title;
            this.description = description;
            this.expected = expected;
        }

        public String getTitle() {
            return title;
        }

        public String getDescription() {
            return description;
        }

        public String getExpected() {
            return expected;
        }
    }

    public record Result(Scenario scenario, String target, List<String> steps) implements java.io.Serializable {
    }

    private record FakeIp(String ip, String country, String code, String city, String isp, boolean proxy,
                          boolean hosting) {
    }

    private static final FakeIp BRUTE_IP =
            new FakeIp("203.0.113.66", "Netherlands", "NL", "Amsterdam", "Simulated Hosting B.V.", false, true);
    private static final FakeIp STUFFING_IP =
            new FakeIp("198.51.100.23", "United States", "US", "Ashburn", "Simulated Cloud LLC", false, true);
    private static final FakeIp VPN_IP =
            new FakeIp("192.0.2.150", "Singapore", "SG", "Singapore", "Simulated VPN Service", true, true);
    private static final List<FakeIp> BOTNET = List.of(
            new FakeIp("203.0.113.11", "Brazil", "BR", "Sao Paulo", "Simulated Telecom BR", false, false),
            new FakeIp("203.0.113.12", "Vietnam", "VN", "Hanoi", "Simulated Broadband VN", false, false),
            new FakeIp("203.0.113.13", "Germany", "DE", "Frankfurt", "Simulated DSL GmbH", false, false),
            new FakeIp("203.0.113.14", "Indonesia", "ID", "Jakarta", "Simulated Net ID", false, false),
            new FakeIp("203.0.113.15", "Poland", "PL", "Warsaw", "Simulated Fibre PL", false, false));

    private static final List<String> LEAKED_EMAILS = List.of(
            "rahul.sharma@example.com", "priya.patel@example.com", "amit.kumar@example.com",
            "sneha.reddy@example.com", "john.smith@example.com", "maria.garcia@example.com",
            "li.wei@example.com", "fatima.khan@example.com", "admin@example.com");

    private static final String UA_HYDRA = "Mozilla/4.0 (Hydra)";
    private static final String UA_PYTHON = "python-requests/2.32.3";
    private static final List<String> UA_HOME_PCS = List.of(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36",
            "Mozilla/5.0 (Linux; Android 14; SM-A546E) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36");
    private static final String UA_VPN_ATTACKER =
            "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";

    private final LoginProtectionService protectionService;
    private final IpIntelService ipIntelService;
    private final UserRepository userRepository;
    private final LoginAttemptRepository attemptRepository;
    private final BlockedIpRepository blockedIpRepository;
    private final AccountLockRepository accountLockRepository;
    private final SecurityAlertRepository alertRepository;
    private final IpInfoRepository ipInfoRepository;
    private final AccountLockService accountLockService;

    public SimulatorService(LoginProtectionService protectionService, IpIntelService ipIntelService,
                            UserRepository userRepository, LoginAttemptRepository attemptRepository,
                            BlockedIpRepository blockedIpRepository, AccountLockRepository accountLockRepository,
                            SecurityAlertRepository alertRepository, IpInfoRepository ipInfoRepository,
                            AccountLockService accountLockService) {
        this.protectionService = protectionService;
        this.ipIntelService = ipIntelService;
        this.userRepository = userRepository;
        this.attemptRepository = attemptRepository;
        this.blockedIpRepository = blockedIpRepository;
        this.accountLockRepository = accountLockRepository;
        this.alertRepository = alertRepository;
        this.ipInfoRepository = ipInfoRepository;
        this.accountLockService = accountLockService;
    }

    /**
     * @throws IllegalArgumentException if the scenario needs an existing account and the target has none
     */
    public Result run(Scenario scenario, String rawTarget) {
        String target = LoginAttemptService.cleanEmail(rawTarget);
        if (target == null) {
            throw new IllegalArgumentException("Please choose a target account.");
        }
        if (scenario == Scenario.ACCOUNT_TAKEOVER && !userRepository.existsByEmail(target)) {
            throw new IllegalArgumentException("Account takeover needs an existing account as the target.");
        }
        List<String> steps = new ArrayList<>();
        if (accountLockService.activeLocks(target).stream().anyMatch(l -> l.getType() == LockType.ACCOUNT)) {
            steps.add("Note: " + target + " is already locked for new IPs. Clear simulated data for a clean run.");
        }
        switch (scenario) {
            case BRUTE_FORCE -> {
                save(BRUTE_IP);
                for (int i = 1; i <= 7; i++) {
                    steps.add(attempt(BRUTE_IP, target, UA_HYDRA, false));
                }
            }
            case CREDENTIAL_STUFFING -> {
                save(STUFFING_IP);
                List<String> emails = new ArrayList<>();
                emails.add(target);
                LEAKED_EMAILS.stream().filter(e -> !e.equals(target)).forEach(emails::add);
                for (String email : emails) {
                    steps.add(attempt(STUFFING_IP, email, UA_PYTHON, false));
                }
            }
            case DISTRIBUTED -> {
                BOTNET.forEach(this::save);
                for (int round = 0; round < 2; round++) {
                    for (int i = 0; i < BOTNET.size(); i++) {
                        steps.add(attempt(BOTNET.get(i), target, UA_HOME_PCS.get(i), false));
                    }
                }
            }
            case ACCOUNT_TAKEOVER -> {
                save(VPN_IP);
                for (int i = 0; i < 3; i++) {
                    steps.add(attempt(VPN_IP, target, UA_VPN_ATTACKER, false));
                }
                steps.add(attempt(VPN_IP, target, UA_VPN_ATTACKER, true));
            }
        }
        return new Result(scenario, target, steps);
    }

    /** Removes everything the simulator created. */
    @Transactional
    public int clear() {
        int removed = attemptRepository.deleteSimulated();
        removed += blockedIpRepository.deleteSimulated();
        removed += accountLockRepository.deleteSimulated();
        removed += alertRepository.deleteSimulated();
        removed += ipInfoRepository.deleteSimulated();
        return removed;
    }

    /** One login attempt through the real pipeline: block check, then success or failure rules. */
    private String attempt(FakeIp from, String email, String userAgent, boolean correctPassword) {
        AttemptContext context = AttemptContext.simulated(from.ip(), email, userAgent);
        String prefix = from.ip() + " (" + from.country() + ") -> " + email + ": ";

        var denial = protectionService.checkBeforeLogin(context.ip(), context.email());
        if (denial.isPresent()) {
            Denial d = denial.get();
            protectionService.recordDenied(context, d);
            return prefix + "REJECTED before password check - " + d.reason().getLabel();
        }
        if (correctPassword) {
            LoginAttempt success = protectionService.onSuccess(context);
            String flags = success.getRiskFlagList().isEmpty() ? "no warning signs"
                    : "risk flags: " + String.join(", ", success.getRiskFlagList().stream().map(f -> f.getLabel()).toList());
            return prefix + "SUCCESSFUL LOGIN with the right password - " + flags;
        }
        AttemptReason reason = userRepository.existsByEmail(email) ? AttemptReason.WRONG_PASSWORD
                : AttemptReason.UNKNOWN_EMAIL;
        FailureResult result = protectionService.onFailure(context, reason);
        return prefix + "failed (" + reason.getLabel().toLowerCase() + ")" + switch (result.action()) {
            case NONE -> "";
            case ACCOUNT_IP_LOCKED -> " -> RULE 1: account locked for this IP";
            case ACCOUNT_LOCKED -> " -> RULE 4: account locked for new IPs";
            case IP_BLOCKED -> " -> IP BLOCKED";
        };
    }

    private void save(FakeIp ip) {
        ipIntelService.saveSimulated(ip.ip(), ip.country(), ip.code(), ip.city(), ip.isp(), ip.proxy(), ip.hosting());
    }
}

package com.example.loginmonitoring.controller;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

import org.springframework.data.domain.Limit;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.example.loginmonitoring.config.DateDisplay;
import com.example.loginmonitoring.config.LoginSecurityProperties;
import com.example.loginmonitoring.dto.KeyCount;
import com.example.loginmonitoring.entity.IpInfo;
import com.example.loginmonitoring.entity.LoginAttempt;
import com.example.loginmonitoring.entity.LoginOutcome;
import com.example.loginmonitoring.entity.Role;
import com.example.loginmonitoring.entity.User;
import com.example.loginmonitoring.repository.LoginAttemptRepository;
import com.example.loginmonitoring.security.ClientIpResolver;
import com.example.loginmonitoring.service.AccountLockService;
import com.example.loginmonitoring.service.AdminAuditService;
import com.example.loginmonitoring.service.AlertService;
import com.example.loginmonitoring.service.AllowlistService;
import com.example.loginmonitoring.service.BlockedIpService;
import com.example.loginmonitoring.service.LoginAttemptService;
import com.example.loginmonitoring.service.SimulatorService;
import com.example.loginmonitoring.service.StatsService;
import com.example.loginmonitoring.service.UserService;
import com.example.loginmonitoring.service.intel.IpIntelService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Security dashboard for administrators (access is restricted to ROLE_ADMIN in SecurityConfig).
 * Every number and row on these pages is read from MySQL on each request.
 * Changes (block, unblock, ...) are handled by {@link AdminActionController}.
 */
@Controller
public class AdminController {

    static final int PAGE_SIZE = 50;
    static final int MAX_CSV_ROWS = 5000;
    static final Duration DAY = Duration.ofHours(24);
    static final Duration WEEK = Duration.ofDays(7);

    /** The IP search box only accepts characters that can appear in an IPv4/IPv6 address. */
    static final Pattern IP_SEARCH = Pattern.compile("^[0-9a-fA-F:.]{1,45}$");
    /** The email search box: printable characters only, no spaces. */
    static final Pattern EMAIL_SEARCH = Pattern.compile("^[^\\s\\p{Cntrl}]{1,150}$");

    /** One row of the Users page. */
    public record UserRow(User user, LoginAttempt lastLogin, long failures24h, boolean locked) {
    }

    private final LoginAttemptService attemptService;
    private final LoginAttemptRepository attemptRepository;
    private final BlockedIpService blockedIpService;
    private final AccountLockService accountLockService;
    private final AllowlistService allowlistService;
    private final AlertService alertService;
    private final AdminAuditService auditService;
    private final StatsService statsService;
    private final IpIntelService ipIntelService;
    private final UserService userService;
    private final LoginSecurityProperties securityProperties;
    private final ClientIpResolver clientIpResolver;
    private final DateDisplay dates;
    private final Clock clock;

    public AdminController(LoginAttemptService attemptService, LoginAttemptRepository attemptRepository,
                           BlockedIpService blockedIpService, AccountLockService accountLockService,
                           AllowlistService allowlistService, AlertService alertService,
                           AdminAuditService auditService, StatsService statsService, IpIntelService ipIntelService,
                           UserService userService, LoginSecurityProperties securityProperties,
                           ClientIpResolver clientIpResolver, DateDisplay dates, Clock clock) {
        this.attemptService = attemptService;
        this.attemptRepository = attemptRepository;
        this.blockedIpService = blockedIpService;
        this.accountLockService = accountLockService;
        this.allowlistService = allowlistService;
        this.alertService = alertService;
        this.auditService = auditService;
        this.statsService = statsService;
        this.ipIntelService = ipIntelService;
        this.userService = userService;
        this.securityProperties = securityProperties;
        this.clientIpResolver = clientIpResolver;
        this.dates = dates;
        this.clock = clock;
    }

    // ---------------------------------------------------------------- overview

    @GetMapping("/admin")
    public String overview(@RequestParam(name = "range", required = false) String range,
                           HttpServletRequest request, Model model) {
        boolean week = "7d".equals(range);

        // Summary cards (all time, plus the last 24 hours)
        model.addAttribute("totalAttempts", attemptService.countAll());
        model.addAttribute("failedAttempts", attemptService.countByOutcome(LoginOutcome.FAILED));
        model.addAttribute("successfulAttempts", attemptService.countByOutcome(LoginOutcome.SUCCESS));
        model.addAttribute("blockedRequests", attemptService.countByOutcome(LoginOutcome.BLOCKED));
        model.addAttribute("attempts24h", statsService.countSince(DAY));
        model.addAttribute("failed24h", statsService.countSince(LoginOutcome.FAILED, DAY));
        model.addAttribute("success24h", statsService.countSince(LoginOutcome.SUCCESS, DAY));
        model.addAttribute("blocked24h", statsService.countSince(LoginOutcome.BLOCKED, DAY));
        model.addAttribute("activeBlockedIps", blockedIpService.countActiveBlockedIps());
        model.addAttribute("activeLocks", accountLockService.countActive());

        // Charts and top lists
        model.addAttribute("week", week);
        model.addAttribute("chart", statsService.activityChart(week));
        model.addAttribute("topIps", statsService.topAttackingIps(week ? WEEK : DAY, 8));
        model.addAttribute("topAccounts", statsService.topTargetedAccounts(week ? WEEK : DAY, 8));
        model.addAttribute("countries", statsService.countries(week ? WEEK : DAY, 8));
        model.addAttribute("recentAlerts", alertService.open(6));
        model.addAttribute("activeBlocks", blockedIpService.activeBlocks());

        // Live feed (refreshed by dashboard.js)
        List<LoginAttempt> feed = attemptService.latest(15);
        model.addAttribute("feed", feed);
        model.addAttribute("info", infoFor(feed));
        model.addAttribute("lastId", feed.isEmpty() ? 0 : feed.get(0).getId());

        addRules(model);
        addConnectionCheck(request, model);
        model.addAttribute("generatedAt", LocalDateTime.now(clock));
        return "admin/overview";
    }

    /** New attempts since {@code after}, for the live feed. */
    @GetMapping("/admin/api/feed")
    @ResponseBody
    public Map<String, Object> feed(@RequestParam(name = "after", defaultValue = "0") long after) {
        List<LoginAttempt> rows = attemptService.newerThan(after, 20);
        Map<String, IpInfo> info = infoFor(rows);
        List<Map<String, Object>> items = new ArrayList<>();
        for (LoginAttempt a : rows) {
            IpInfo ipInfo = info.get(a.getIpAddress());
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("id", a.getId());
            item.put("time", dates.format(a.getAttemptedAt()));
            item.put("ip", a.getIpAddress());
            item.put("email", a.getAttemptedEmail() == null ? "-" : a.getAttemptedEmail());
            item.put("outcome", a.getOutcome().name());
            item.put("reason", a.getReason() == null ? "" : a.getReason().getLabel());
            item.put("location", (ipInfo.getFlag() + " " + ipInfo.getLocationLabel()).trim());
            item.put("device", a.getDeviceLabel());
            item.put("simulated", a.isSimulated());
            item.put("risk", a.getRiskScore() == null ? 0 : a.getRiskScore());
            items.add(item);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("lastId", rows.isEmpty() ? after : rows.get(0).getId());
        body.put("items", items);
        body.put("activeBlockedIps", blockedIpService.countActiveBlockedIps());
        body.put("activeLocks", accountLockService.countActive());
        body.put("openAlerts", alertService.countOpen());
        body.put("attempts24h", statsService.countSince(DAY));
        body.put("generatedAt", dates.format(LocalDateTime.now(clock)));
        return body;
    }

    // ---------------------------------------------------------------- attempt log

    @GetMapping("/admin/attempts")
    public String attempts(@RequestParam(name = "status", required = false) String status,
                           @RequestParam(name = "ip", required = false) String ip,
                           @RequestParam(name = "email", required = false) String email,
                           @RequestParam(name = "page", defaultValue = "0") int page,
                           Model model) {
        Filters filters = Filters.parse(status, ip, email);
        Page<LoginAttempt> result = attemptService.search(filters.outcome(), filters.ip(), filters.email(),
                Math.max(0, Math.min(page, 10_000)), PAGE_SIZE);

        model.addAttribute("page", result);
        model.addAttribute("attempts", result.getContent());
        model.addAttribute("info", infoFor(result.getContent()));
        model.addAttribute("statusFilter", filters.outcome() == null ? "ALL" : filters.outcome().name());
        model.addAttribute("ipFilter", filters.ipText());
        model.addAttribute("emailFilter", filters.emailText());
        model.addAttribute("ipFilterInvalid", filters.ipInvalid());
        model.addAttribute("emailFilterInvalid", filters.emailInvalid());
        model.addAttribute("outcomes", LoginOutcome.values());
        model.addAttribute("pageSize", PAGE_SIZE);
        return "admin/attempts";
    }

    /** The same list as a CSV file for Excel. */
    @GetMapping("/admin/attempts.csv")
    public void attemptsCsv(@RequestParam(name = "status", required = false) String status,
                            @RequestParam(name = "ip", required = false) String ip,
                            @RequestParam(name = "email", required = false) String email,
                            HttpServletResponse response) throws IOException {
        Filters filters = Filters.parse(status, ip, email);
        List<LoginAttempt> rows = attemptService.search(filters.outcome(), filters.ip(), filters.email(), 0,
                MAX_CSV_ROWS).getContent();
        Map<String, IpInfo> info = infoFor(rows);

        response.setContentType("text/csv");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setHeader("Content-Disposition", "attachment; filename=\"login-attempts.csv\"");
        PrintWriter out = response.getWriter();
        out.write('﻿'); // so Excel reads UTF-8 correctly
        out.println("id,time_utc,ip_address,email,outcome,reason,country,city,isp,browser,os,device,risk_flags,simulated");
        for (LoginAttempt a : rows) {
            IpInfo i = info.get(a.getIpAddress());
            out.println(String.join(",", csv(a.getId()), csv(a.getAttemptedAt()), csv(a.getIpAddress()),
                    csv(a.getAttemptedEmail()), csv(a.getOutcome()), csv(a.getReason()), csv(i.getCountry()),
                    csv(i.getCity()), csv(i.getIsp()), csv(a.getBrowser()), csv(a.getOs()), csv(a.getDeviceType()),
                    csv(a.getRiskFlags()), csv(a.isSimulated())));
        }
        out.flush();
    }

    // ---------------------------------------------------------------- one IP

    @GetMapping("/admin/ip")
    public String ipDetail(@RequestParam(name = "ip", required = false) String rawIp, HttpServletRequest request,
                           Model model) {
        String ip = ClientIpResolver.normalize(rawIp);
        if (ip == null) {
            model.addAttribute("invalidIp", rawIp == null ? "" : rawIp);
            return "admin/ip";
        }
        LocalDateTime now = LocalDateTime.now(clock);
        model.addAttribute("ip", ip);
        model.addAttribute("ipInfo", ipIntelService.describe(ip));
        model.addAttribute("total", attemptRepository.countByIpAddress(ip));
        model.addAttribute("failed", attemptRepository.countByIpAddressAndOutcome(ip, LoginOutcome.FAILED));
        model.addAttribute("success", attemptRepository.countByIpAddressAndOutcome(ip, LoginOutcome.SUCCESS));
        model.addAttribute("blocked", attemptRepository.countByIpAddressAndOutcome(ip, LoginOutcome.BLOCKED));
        model.addAttribute("firstSeen", attemptRepository.firstSeen(ip));
        model.addAttribute("lastSeen", attemptRepository.lastSeen(ip));
        model.addAttribute("activeBlock", blockedIpService.findActiveBlock(ip).orElse(null));
        model.addAttribute("blockHistory", blockedIpService.historyFor(ip, 20));
        model.addAttribute("locks", accountLockService.forIp(ip, 20));
        model.addAttribute("emailsTried", attemptRepository.emailsTriedFromIp(ip, Limit.of(30)));
        model.addAttribute("attempts", attemptRepository.findByIpAddressOrderByAttemptedAtDescIdDesc(ip, Limit.of(50)));
        model.addAttribute("alerts", alertService.forIp(ip, 20));
        model.addAttribute("allowlisted", allowlistService.isAllowlisted(ip));
        model.addAttribute("isMyIp", ip.equals(clientIpResolver.resolve(request)));
        model.addAttribute("now", now);
        return "admin/ip";
    }

    // ---------------------------------------------------------------- protection

    @GetMapping("/admin/protection")
    public String protection(HttpServletRequest request, Model model) {
        model.addAttribute("activeBlocks", blockedIpService.activeBlocks());
        model.addAttribute("blockHistory", blockedIpService.search(null, 50));
        model.addAttribute("activeLocks", accountLockService.allActive());
        model.addAttribute("recentLocks", accountLockService.recent(30));
        model.addAttribute("allowlist", allowlistService.all());
        model.addAttribute("now", LocalDateTime.now(clock));
        model.addAttribute("yourIp", clientIpResolver.resolve(request));
        addRules(model);
        return "admin/protection";
    }

    // ---------------------------------------------------------------- alerts

    @GetMapping("/admin/alerts")
    public String alerts(@RequestParam(name = "show", defaultValue = "open") String show, Model model) {
        boolean all = "all".equals(show);
        model.addAttribute("showAll", all);
        model.addAttribute("alerts", all ? alertService.recent(200) : alertService.open(200));
        return "admin/alerts";
    }

    // ---------------------------------------------------------------- users

    @GetMapping("/admin/users")
    public String users(Model model) {
        LocalDateTime now = LocalDateTime.now(clock);
        List<User> users = userService.allUsers();
        List<String> emails = users.stream().map(User::getEmail).toList();
        Map<String, Long> failures = new LinkedHashMap<>();
        if (!emails.isEmpty()) {
            for (KeyCount row : attemptRepository.failuresForEmails(emails, now.minus(DAY))) {
                failures.put(row.key(), row.count());
            }
        }
        List<UserRow> rows = users.stream().map(u -> new UserRow(u, lastLogin(u.getEmail()),
                failures.getOrDefault(u.getEmail(), 0L),
                !accountLockService.activeLocks(u.getEmail()).isEmpty())).toList();
        model.addAttribute("rows", rows);
        model.addAttribute("roles", Role.values());
        return "admin/users";
    }

    // ---------------------------------------------------------------- simulator + audit

    @GetMapping("/admin/simulator")
    public String simulator(Model model) {
        model.addAttribute("scenarios", SimulatorService.Scenario.values());
        model.addAttribute("users", userService.allUsers().stream()
                .sorted((a, b) -> Boolean.compare(a.getRole() == Role.ADMIN, b.getRole() == Role.ADMIN))
                .toList());
        addRules(model);
        return "admin/simulator";
    }

    @GetMapping("/admin/audit")
    public String audit(Model model) {
        model.addAttribute("actions", auditService.recent(200));
        return "admin/audit";
    }

    // ---------------------------------------------------------------- helpers

    private LoginAttempt lastLogin(String email) {
        List<LoginAttempt> last = attemptRepository.findTop2ByAttemptedEmailAndOutcomeOrderByAttemptedAtDescIdDesc(
                email, LoginOutcome.SUCCESS);
        return last.isEmpty() ? null : last.get(0);
    }

    private Map<String, IpInfo> infoFor(List<LoginAttempt> attempts) {
        return ipIntelService.describeAll(attempts.stream().map(LoginAttempt::getIpAddress).toList());
    }

    private void addRules(Model model) {
        model.addAttribute("maxAttempts", securityProperties.maxFailedAttempts());
        model.addAttribute("windowMinutes", securityProperties.monitoringWindow().toMinutes());
        model.addAttribute("blockMinutes", securityProperties.blockDuration().toMinutes());
        model.addAttribute("ipMaxAccounts", securityProperties.ipMaxAccounts());
        model.addAttribute("ipMaxFailures", securityProperties.ipMaxFailures());
        model.addAttribute("accountMaxFailures", securityProperties.accountMaxFailures());
        model.addAttribute("accountMinIps", securityProperties.accountMinIps());
        model.addAttribute("repeatBlocks", securityProperties.repeatBlockDurations().stream()
                .map(com.example.loginmonitoring.service.LoginProtectionService::describe).toList());
    }

    /** Shows how the visitor IP was found, so the proxy setup can be checked after deployment. */
    private void addConnectionCheck(HttpServletRequest request, Model model) {
        ClientIpResolver.Resolution resolution = clientIpResolver.resolveDetailed(request);
        model.addAttribute("yourIp", resolution.ip());
        model.addAttribute("ipMethod", resolution.method());
        model.addAttribute("connectionIp", resolution.remoteAddress());
        model.addAttribute("ipHeaders", resolution.headers());
        model.addAttribute("onRender", clientIpResolver.isRender());
        model.addAttribute("yourIpInfo", ipIntelService.describe(resolution.ip()));
        model.addAttribute("yourIpPublic", com.example.loginmonitoring.service.intel.IpClassifier.isPublic(resolution.ip()));
    }

    /** Values for CSV cells. Cells starting with = + - @ are prefixed so Excel does not run them as formulas. */
    static String csv(Object value) {
        if (value == null) {
            return "";
        }
        String text = value.toString();
        if (!text.isEmpty() && "=+-@\t\r".indexOf(text.charAt(0)) >= 0) {
            text = "'" + text;
        }
        if (text.contains(",") || text.contains("\"") || text.contains("\n") || text.contains("\r")) {
            text = "\"" + text.replace("\"", "\"\"") + "\"";
        }
        return text;
    }

    /** The search boxes of the attempt log, checked. */
    record Filters(LoginOutcome outcome, String ip, String email, String ipText, String emailText,
                   boolean ipInvalid, boolean emailInvalid) {

        static Filters parse(String status, String ip, String email) {
            LoginOutcome outcome = parseOutcome(status);
            String ipText = ip == null || ip.isBlank() ? null : ip.trim();
            boolean ipInvalid = ipText != null && !IP_SEARCH.matcher(ipText).matches();
            String emailText = email == null || email.isBlank() ? null : email.trim().toLowerCase(Locale.ROOT);
            boolean emailInvalid = emailText != null && !EMAIL_SEARCH.matcher(emailText).matches();
            return new Filters(outcome, ipInvalid ? null : ipText, emailInvalid ? null : emailText,
                    ipText, emailText, ipInvalid, emailInvalid);
        }

        private static LoginOutcome parseOutcome(String status) {
            if (status == null || status.isBlank() || "ALL".equalsIgnoreCase(status)) {
                return null;
            }
            try {
                return LoginOutcome.valueOf(status.trim().toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException ex) {
                return null;
            }
        }
    }

    static Optional<Duration> parseDuration(String value) {
        return switch (value == null ? "" : value) {
            case "15m" -> Optional.of(Duration.ofMinutes(15));
            case "1h" -> Optional.of(Duration.ofHours(1));
            case "24h" -> Optional.of(Duration.ofHours(24));
            case "7d" -> Optional.of(Duration.ofDays(7));
            default -> Optional.empty();
        };
    }
}

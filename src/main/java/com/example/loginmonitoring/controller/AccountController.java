package com.example.loginmonitoring.controller;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.example.loginmonitoring.dto.ChangePasswordForm;
import com.example.loginmonitoring.entity.AccountLock;
import com.example.loginmonitoring.entity.AlertSeverity;
import com.example.loginmonitoring.entity.AlertType;
import com.example.loginmonitoring.entity.BlockSource;
import com.example.loginmonitoring.entity.IpInfo;
import com.example.loginmonitoring.entity.LockType;
import com.example.loginmonitoring.entity.LoginAttempt;
import com.example.loginmonitoring.entity.LoginOutcome;
import com.example.loginmonitoring.entity.Role;
import com.example.loginmonitoring.entity.User;
import com.example.loginmonitoring.security.ClientIpResolver;
import com.example.loginmonitoring.security.LoginSuccessHandler;
import com.example.loginmonitoring.service.AccountLockService;
import com.example.loginmonitoring.service.AlertService;
import com.example.loginmonitoring.service.AllowlistService;
import com.example.loginmonitoring.service.BlockedIpService;
import com.example.loginmonitoring.service.LoginAttemptService;
import com.example.loginmonitoring.service.SessionTracker;
import com.example.loginmonitoring.service.UserService;
import com.example.loginmonitoring.service.intel.BreachedPasswordService;
import com.example.loginmonitoring.service.intel.IpIntelService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;

/**
 * The signed-in user's own pages: dashboard with login activity and active sessions,
 * "This wasn't me", and change password.
 */
@Controller
public class AccountController {

    static final int ACTIVITY_ROWS = 25;
    static final Duration REPORT_BLOCK = Duration.ofHours(24);

    /** One row of "Recent login activity". */
    public record ActivityRow(LoginAttempt attempt, IpInfo info, boolean currentLogin, boolean canReport) {
    }

    private final UserService userService;
    private final LoginAttemptService attemptService;
    private final IpIntelService ipIntelService;
    private final SessionTracker sessionTracker;
    private final AccountLockService accountLockService;
    private final BlockedIpService blockedIpService;
    private final AllowlistService allowlistService;
    private final AlertService alertService;
    private final BreachedPasswordService breachedPasswordService;
    private final ClientIpResolver clientIpResolver;
    private final Clock clock;

    public AccountController(UserService userService, LoginAttemptService attemptService, IpIntelService ipIntelService,
                             SessionTracker sessionTracker, AccountLockService accountLockService,
                             BlockedIpService blockedIpService, AllowlistService allowlistService,
                             AlertService alertService, BreachedPasswordService breachedPasswordService,
                             ClientIpResolver clientIpResolver, Clock clock) {
        this.userService = userService;
        this.attemptService = attemptService;
        this.ipIntelService = ipIntelService;
        this.sessionTracker = sessionTracker;
        this.accountLockService = accountLockService;
        this.blockedIpService = blockedIpService;
        this.allowlistService = allowlistService;
        this.alertService = alertService;
        this.breachedPasswordService = breachedPasswordService;
        this.clientIpResolver = clientIpResolver;
        this.clock = clock;
    }

    @GetMapping("/dashboard")
    public String dashboard(Authentication authentication, HttpSession session, Model model) {
        User user = currentUser(authentication);
        Long currentLoginId = (Long) session.getAttribute(LoginSuccessHandler.LOGIN_ATTEMPT_ATTRIBUTE);

        // Only the fields the page needs; the password hash never reaches the template.
        model.addAttribute("name", user.getName());
        model.addAttribute("email", user.getEmail());
        model.addAttribute("createdAt", user.getCreatedAt());
        model.addAttribute("isAdmin", user.getRole() == Role.ADMIN);

        // "Last login" = the login before the one that started THIS session (other logins that happened
        // while this session was open are still listed - and flagged - in the activity table)
        Optional<LoginAttempt> previousLogin = currentLoginId != null
                ? attemptService.findSuccessfulLoginBefore(user.getEmail(), currentLoginId)
                : attemptService.findPreviousSuccessfulLogin(user.getEmail());
        model.addAttribute("previousLogin", previousLogin.orElse(null));
        model.addAttribute("previousLoginLocation",
                previousLogin.map(p -> ipIntelService.describe(p.getIpAddress()).getLocationLabel()).orElse(null));

        // "N failed attempts since your last login" warning
        LocalDateTime since = previousLogin.map(LoginAttempt::getAttemptedAt).orElse(user.getCreatedAt());
        model.addAttribute("failedSinceLastLogin", attemptService.countUnsuccessfulSince(user.getEmail(), since));

        List<LoginAttempt> activity = attemptService.activityFor(user.getEmail(), ACTIVITY_ROWS);
        Map<String, IpInfo> info = ipIntelService.describeAll(activity.stream().map(LoginAttempt::getIpAddress).toList());
        model.addAttribute("activity", activity.stream().map(a -> {
            boolean current = a.getId().equals(currentLoginId);
            boolean canReport = a.getOutcome() == LoginOutcome.SUCCESS && !current && !a.isReported();
            return new ActivityRow(a, info.get(a.getIpAddress()), current, canReport);
        }).toList());

        model.addAttribute("sessions", sessionTracker.sessionsOf(user.getEmail(), session.getId()));

        LocalDateTime now = LocalDateTime.now(clock);
        Optional<AccountLock> underAttack = accountLockService.activeLocks(user.getEmail()).stream()
                .filter(lock -> lock.getType() == LockType.ACCOUNT && lock.isActiveAt(now)).findFirst();
        model.addAttribute("underAttackUntil", underAttack.map(AccountLock::getExpiresAt).orElse(null));
        return "dashboard";
    }

    @PostMapping("/account/sessions/signout-others")
    public String signOutOthers(Authentication authentication, HttpSession session, RedirectAttributes redirect) {
        int count = sessionTracker.expireOthers(authentication.getName(), session.getId());
        redirect.addFlashAttribute("message", count == 0 ? "No other sessions were open."
                : "Signed out " + count + " other session" + (count == 1 ? "" : "s") + ".");
        return "redirect:/dashboard";
    }

    @PostMapping("/account/sessions/signout")
    public String signOutOne(@RequestParam("handle") String handle, Authentication authentication,
                             RedirectAttributes redirect) {
        boolean done = sessionTracker.expireByHandle(authentication.getName(), handle);
        redirect.addFlashAttribute("message", done ? "That session was signed out." : "Session not found.");
        return "redirect:/dashboard";
    }

    /**
     * "This wasn't me": signs out every other session, blocks the IP of the reported login for 24 h
     * (unless it is the IP the user is using right now), raises an alert and asks for a new password.
     */
    @PostMapping("/account/report/{id}")
    public String reportLogin(@PathVariable("id") long id, Authentication authentication, HttpSession session,
                              HttpServletRequest request, RedirectAttributes redirect) {
        String email = authentication.getName();
        Optional<LoginAttempt> found = attemptService.findById(id);
        Long currentLoginId = (Long) session.getAttribute(LoginSuccessHandler.LOGIN_ATTEMPT_ATTRIBUTE);
        if (found.isEmpty() || !email.equalsIgnoreCase(found.get().getAttemptedEmail())
                || found.get().getOutcome() != LoginOutcome.SUCCESS || found.get().getId().equals(currentLoginId)) {
            redirect.addFlashAttribute("error", "That login cannot be reported.");
            return "redirect:/dashboard";
        }
        LoginAttempt attempt = found.get();
        attemptService.markReported(id);
        int signedOut = sessionTracker.expireOthers(email, session.getId());

        String reportedIp = attempt.getIpAddress();
        String myIp = clientIpResolver.resolve(request);
        String location = ipIntelService.describe(reportedIp).getLocationLabel();
        String blockNote;
        if (reportedIp.equals(myIp)) {
            blockNote = "The IP was not blocked because it is the network you are using right now.";
        } else if (allowlistService.isAllowlisted(reportedIp)) {
            blockNote = "The IP was not blocked because the administrator marked it as trusted.";
        } else {
            if (!blockedIpService.isBlocked(reportedIp)) {
                blockedIpService.blockManually(reportedIp, REPORT_BLOCK,
                        "Reported by the account owner (\"This wasn't me\")", BlockSource.USER_REPORT, email,
                        attempt.isSimulated());
            }
            blockNote = "IP " + reportedIp + " has been blocked for 24 hours.";
        }
        alertService.raise(AlertType.USER_REPORTED, AlertSeverity.HIGH, reportedIp, email,
                email + " reported the login from " + reportedIp + " (" + location + ") as NOT theirs. "
                        + signedOut + " other session(s) signed out. " + blockNote, attempt.isSimulated());

        redirect.addFlashAttribute("reported", "Thanks for telling us. We signed out " + signedOut
                + " other session(s). " + blockNote + " Please choose a new password now.");
        return "redirect:/account/password";
    }

    @GetMapping("/account/password")
    public String passwordPage(Authentication authentication, Model model) {
        model.addAttribute("form", new ChangePasswordForm());
        model.addAttribute("isAdmin", currentUser(authentication).getRole() == Role.ADMIN);
        return "password";
    }

    @PostMapping("/account/password")
    public String changePassword(@Valid @ModelAttribute("form") ChangePasswordForm form, BindingResult result,
                                 Authentication authentication, HttpSession session, Model model,
                                 RedirectAttributes redirect) {
        User user = currentUser(authentication);
        if (!result.hasFieldErrors("currentPassword")
                && !userService.passwordMatches(user.getEmail(), form.getCurrentPassword())) {
            result.rejectValue("currentPassword", "wrong", "Your current password is not correct.");
        }
        if (form.getNewPassword() != null && !form.getNewPassword().equals(form.getConfirmPassword())) {
            result.rejectValue("confirmPassword", "mismatch", "Passwords do not match.");
        }
        if (form.getNewPassword() != null
                && form.getNewPassword().getBytes(StandardCharsets.UTF_8).length > AuthController.MAX_PASSWORD_BYTES) {
            result.rejectValue("newPassword", "tooLong", "Password is too long. Please use a shorter password.");
        }
        if (form.getNewPassword() != null && form.getNewPassword().equals(form.getCurrentPassword())) {
            result.rejectValue("newPassword", "same", "The new password must be different from the current one.");
        }
        if (!result.hasFieldErrors("newPassword")) {
            AuthController.rejectIfBreached(breachedPasswordService, form.getNewPassword(), result, "newPassword");
        }
        if (result.hasErrors()) {
            form.clearPasswords();
            model.addAttribute("isAdmin", user.getRole() == Role.ADMIN);
            return "password";
        }

        userService.changePassword(user.getEmail(), form.getNewPassword());
        int signedOut = sessionTracker.expireOthers(user.getEmail(), session.getId());
        redirect.addFlashAttribute("message", "Your password was changed."
                + (signedOut > 0 ? " " + signedOut + " other session(s) were signed out." : ""));
        return "redirect:/dashboard";
    }

    private User currentUser(Authentication authentication) {
        return userService.findByEmail(authentication.getName())
                .orElseThrow(() -> new IllegalStateException("Logged-in user no longer exists"));
    }
}

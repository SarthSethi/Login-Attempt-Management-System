package com.example.loginmonitoring.controller;

import java.nio.charset.StandardCharsets;
import java.util.OptionalLong;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.loginmonitoring.config.LoginSecurityProperties;
import com.example.loginmonitoring.dto.RegistrationRequest;
import com.example.loginmonitoring.security.ClientIpResolver;
import com.example.loginmonitoring.security.LoginRedirects;
import com.example.loginmonitoring.service.EmailAlreadyRegisteredException;
import com.example.loginmonitoring.service.LoginAttemptService;
import com.example.loginmonitoring.service.LoginProtectionService;
import com.example.loginmonitoring.service.LoginStatus;
import com.example.loginmonitoring.service.UserService;
import com.example.loginmonitoring.service.intel.BreachedPasswordService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;

/**
 * Login and registration pages. The login form itself is processed by Spring Security
 * (POST /login), not by this controller.
 */
@Controller
public class AuthController {

    /** BCrypt's input limit. */
    static final int MAX_PASSWORD_BYTES = 72;

    private final UserService userService;
    private final LoginSecurityProperties securityProperties;
    private final BreachedPasswordService breachedPasswordService;
    private final LoginProtectionService protectionService;
    private final ClientIpResolver clientIpResolver;

    public AuthController(UserService userService, LoginSecurityProperties securityProperties,
                          BreachedPasswordService breachedPasswordService, LoginProtectionService protectionService,
                          ClientIpResolver clientIpResolver) {
        this.userService = userService;
        this.securityProperties = securityProperties;
        this.breachedPasswordService = breachedPasswordService;
        this.protectionService = protectionService;
        this.clientIpResolver = clientIpResolver;
    }

    @GetMapping("/")
    public String home() {
        return "redirect:/dashboard";
    }

    @GetMapping("/login")
    public String loginPage(@RequestParam(name = "clear", required = false) String clear,
                            Authentication authentication, HttpServletRequest request, Model model) {
        if (authentication != null && authentication.isAuthenticated()) {
            return "redirect:/dashboard";
        }
        HttpSession session = request.getSession(false);
        if (clear != null) {
            if (session != null) {
                session.removeAttribute(LoginRedirects.LAST_EMAIL);
            }
            return "redirect:/login";
        }
        String lastEmail = session == null ? null : (String) session.getAttribute(LoginRedirects.LAST_EMAIL);

        // Read from the database every time, so refreshing the page shows the same counter
        LoginStatus status = protectionService.statusFor(clientIpResolver.resolve(request),
                LoginAttemptService.cleanEmail(lastEmail));
        model.addAttribute("status", status);
        model.addAttribute("lastEmail", lastEmail);
        model.addAttribute("windowMinutes", securityProperties.monitoringWindow().toMinutes());
        model.addAttribute("blockMinutes", securityProperties.blockDuration().toMinutes());
        return "login";
    }

    @GetMapping("/register")
    public String registerPage(Authentication authentication, Model model) {
        if (authentication != null && authentication.isAuthenticated()) {
            return "redirect:/dashboard";
        }
        model.addAttribute("form", new RegistrationRequest());
        return "register";
    }

    @PostMapping("/register")
    public String register(@Valid @ModelAttribute("form") RegistrationRequest form, BindingResult result) {
        if (form.getPassword() != null && !form.getPassword().equals(form.getConfirmPassword())) {
            result.rejectValue("confirmPassword", "mismatch", "Passwords do not match.");
        }
        // BCrypt only uses the first 72 bytes; non-English characters take 2-4 bytes each
        if (form.getPassword() != null
                && form.getPassword().getBytes(StandardCharsets.UTF_8).length > MAX_PASSWORD_BYTES) {
            result.rejectValue("password", "tooLong", "Password is too long. Please use a shorter password.");
        }
        if (!result.hasFieldErrors("password")) {
            rejectIfBreached(breachedPasswordService, form.getPassword(), result, "password");
        }

        if (!result.hasErrors()) {
            try {
                userService.register(form);
                return "redirect:/login?registered";
            } catch (EmailAlreadyRegisteredException | DataIntegrityViolationException ex) {
                result.rejectValue("email", "duplicate", "This email is already registered. Please log in instead.");
            }
        }

        // Never send typed passwords back to the browser
        form.setPassword(null);
        form.setConfirmPassword(null);
        return "register";
    }

    /** Adds a form error if the password appears in known data breaches. */
    static void rejectIfBreached(BreachedPasswordService service, String password, BindingResult result, String field) {
        OptionalLong breaches = service.breachCount(password);
        if (breaches.isPresent() && breaches.getAsLong() > 0) {
            result.rejectValue(field, "breached", String.format(
                    "This password has appeared in %,d known data breaches. Please choose a different one.",
                    breaches.getAsLong()));
        }
    }
}

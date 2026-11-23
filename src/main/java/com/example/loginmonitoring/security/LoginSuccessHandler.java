package com.example.loginmonitoring.security;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.example.loginmonitoring.entity.LoginAttempt;
import com.example.loginmonitoring.service.AttemptContext;
import com.example.loginmonitoring.service.LoginProtectionService;
import com.example.loginmonitoring.service.SessionTracker;
import com.example.loginmonitoring.service.intel.IpIntelService;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

/**
 * Called by Spring Security after the email and password were verified.
 * Records a SUCCESS attempt (with risk flags), remembers the device for the "active sessions"
 * list and sends the user to their dashboard (administrators go to /admin).
 */
@Component
public class LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    /** Session attribute holding the id of the login attempt that started this session. */
    public static final String LOGIN_ATTEMPT_ATTRIBUTE = "lams.loginAttemptId";

    private final ClientIpResolver clientIpResolver;
    private final LoginProtectionService protectionService;
    private final SessionTracker sessionTracker;
    private final IpIntelService ipIntelService;

    public LoginSuccessHandler(ClientIpResolver clientIpResolver, LoginProtectionService protectionService,
                               SessionTracker sessionTracker, IpIntelService ipIntelService) {
        this.clientIpResolver = clientIpResolver;
        this.protectionService = protectionService;
        this.sessionTracker = sessionTracker;
        this.ipIntelService = ipIntelService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        AttemptContext context = AttemptContext.real(clientIpResolver.resolve(request), authentication.getName(),
                request.getHeader("User-Agent"));
        LoginAttempt attempt = protectionService.onSuccess(context);

        HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute(LoginRedirects.LAST_EMAIL);
            session.setAttribute(LOGIN_ATTEMPT_ATTRIBUTE, attempt.getId());
            sessionTracker.register(session.getId(), authentication.getName(), attempt,
                    ipIntelService.describe(context.ip()).getLocationLabel());
        }
        super.onAuthenticationSuccess(request, response, authentication);
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) {
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(authority -> "ROLE_ADMIN".equals(authority.getAuthority()));
        return isAdmin ? "/admin" : "/dashboard";
    }
}

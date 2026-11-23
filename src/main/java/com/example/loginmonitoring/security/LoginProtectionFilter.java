package com.example.loginmonitoring.security;

import java.io.IOException;
import java.util.Optional;

import org.springframework.http.HttpMethod;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.loginmonitoring.service.AttemptContext;
import com.example.loginmonitoring.service.LoginProtectionService;
import com.example.loginmonitoring.service.LoginProtectionService.Denial;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Runs for every "POST /login" request BEFORE Spring Security checks the email and password.
 *
 * <p>If the IP is blocked, or the account is locked for this IP, the request is stopped here:
 * the attempt is saved with outcome BLOCKED and the browser is sent back to the login page with
 * a message. The rest of the filter chain (including UsernamePasswordAuthenticationFilter) never
 * runs, so the credentials are not checked at all - even correct ones are rejected.
 *
 * <p>This class is created in {@code SecurityConfig} and deliberately NOT annotated with
 * {@code @Component}; otherwise Spring Boot would also register it as a plain servlet filter
 * that runs outside (before) the Spring Security chain and its CSRF check.
 */
public class LoginProtectionFilter extends OncePerRequestFilter {

    private final RequestMatcher loginRequest =
            PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/login");

    private final ClientIpResolver clientIpResolver;
    private final LoginProtectionService protectionService;

    public LoginProtectionFilter(ClientIpResolver clientIpResolver, LoginProtectionService protectionService) {
        this.clientIpResolver = clientIpResolver;
        this.protectionService = protectionService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !loginRequest.matches(request);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        AttemptContext context = AttemptContext.real(clientIpResolver.resolve(request),
                request.getParameter(LoginFormFields.EMAIL), request.getHeader("User-Agent"));

        Optional<Denial> denial = protectionService.checkBeforeLogin(context.ip(), context.email());
        if (denial.isPresent()) {
            protectionService.recordDenied(context, denial.get());
            LoginRedirects.rememberEmail(request, context.email());
            response.sendRedirect(request.getContextPath() + LoginRedirects.forDenial(denial.get()));
            return; // stop here: credentials are never checked
        }

        chain.doFilter(request, response);
    }
}

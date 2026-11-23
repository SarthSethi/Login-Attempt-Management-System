package com.example.loginmonitoring.security;

import java.io.IOException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import com.example.loginmonitoring.entity.AttemptReason;
import com.example.loginmonitoring.repository.UserRepository;
import com.example.loginmonitoring.service.AttemptContext;
import com.example.loginmonitoring.service.LoginProtectionService;
import com.example.loginmonitoring.service.LoginProtectionService.FailureResult;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Called by Spring Security when the email/password check fails
 * (unknown email, wrong password or disabled account).
 *
 * <p>It records a FAILED attempt and lets {@link LoginProtectionService} apply the rules.
 * For unknown emails and wrong passwords the same generic message is shown, so nobody can find
 * out which emails exist. The real reason is stored for the administrator only.
 */
@Component
public class LoginFailureHandler implements AuthenticationFailureHandler {

    private final ClientIpResolver clientIpResolver;
    private final LoginProtectionService protectionService;
    private final UserRepository userRepository;

    public LoginFailureHandler(ClientIpResolver clientIpResolver, LoginProtectionService protectionService,
                               UserRepository userRepository) {
        this.clientIpResolver = clientIpResolver;
        this.protectionService = protectionService;
        this.userRepository = userRepository;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        String email = request.getParameter(LoginFormFields.EMAIL);
        String password = request.getParameter(LoginFormFields.PASSWORD);

        // An incomplete form is not a password guess, so it is not counted.
        if (isBlank(email) || isBlank(password)) {
            LoginRedirects.rememberEmail(request, isBlank(email) ? null : email.trim());
            redirect(request, response, "/login?missing");
            return;
        }

        AttemptContext context = AttemptContext.real(clientIpResolver.resolve(request), email,
                request.getHeader("User-Agent"));
        AttemptReason reason;
        if (exception instanceof DisabledException) {
            reason = AttemptReason.ACCOUNT_DISABLED;
        } else if (context.email() != null && userRepository.existsByEmail(context.email())) {
            reason = AttemptReason.WRONG_PASSWORD;
        } else {
            reason = AttemptReason.UNKNOWN_EMAIL;
        }

        FailureResult result = protectionService.onFailure(context, reason);
        LoginRedirects.rememberEmail(request, context.email());

        // The login page reads the attempt counter from the database, so only the type of message goes in the URL.
        switch (result.action()) {
            case IP_BLOCKED -> redirect(request, response, "/login?blocked");
            case ACCOUNT_IP_LOCKED, ACCOUNT_LOCKED -> redirect(request, response, "/login?locked");
            case NONE -> redirect(request, response,
                    reason == AttemptReason.ACCOUNT_DISABLED ? "/login?disabled" : "/login?error");
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static void redirect(HttpServletRequest request, HttpServletResponse response, String target)
            throws IOException {
        response.sendRedirect(request.getContextPath() + target);
    }
}

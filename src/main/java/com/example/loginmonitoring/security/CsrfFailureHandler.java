package com.example.loginmonitoring.security;

import java.io.IOException;

import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.csrf.CsrfException;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.example.loginmonitoring.service.LoginAttemptService;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

/**
 * Handles forms whose CSRF token is missing or no longer valid.
 *
 * A token belongs to one session. It stops matching when the session is gone (server restart,
 * redeploy, the free Render instance waking up, 30 minutes without activity) or when the user
 * signed in or out in another tab. Spring's default answer is a bare 403 page, which looks like
 * "access denied" even though nothing was checked. Instead:
 * <ul>
 *   <li>sign-in form: back to the sign-in page with the email filled in; the password is not
 *       checked and the attempt is not counted</li>
 *   <li>sign-out without a session: the user is already signed out</li>
 *   <li>registration form: back to the form</li>
 *   <li>any other form after the session ended: sign in again</li>
 *   <li>signed-in user with an old token (another tab): 403 page saying the form expired</li>
 * </ul>
 * The request is refused in every case, so CSRF protection is unchanged. Real "wrong role" denials
 * still get the normal 403 page.
 */
public class CsrfFailureHandler implements AccessDeniedHandler {

    /** Request attribute read by error/403.html to show the "form expired" text. */
    public static final String FORM_EXPIRED = "lamsFormExpired";

    private final AccessDeniedHandler defaultHandler = new AccessDeniedHandlerImpl();
    private final RequestMatcher loginForm = post("/login");
    private final RequestMatcher logoutForm = post("/logout");
    private final RequestMatcher registerForm = post("/register");

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException exception) throws IOException, ServletException {
        if (!(exception instanceof CsrfException) || response.isCommitted()) {
            defaultHandler.handle(request, response, exception);
            return;
        }

        String target;
        if (loginForm.matches(request)) {
            String email = LoginAttemptService.cleanEmail(request.getParameter(LoginFormFields.EMAIL));
            // Spring's CSRF filter has already created a session for its new token; reuse it, never make one here
            HttpSession session = request.getSession(false);
            if (email != null && session != null) {
                session.setAttribute(LoginRedirects.LAST_EMAIL, email);
            }
            target = "/login?retry";
        } else if (signedIn()) {
            request.setAttribute(FORM_EXPIRED, Boolean.TRUE);
            defaultHandler.handle(request, response, exception);
            return;
        } else if (logoutForm.matches(request)) {
            target = "/login?logout";
        } else if (registerForm.matches(request)) {
            target = "/register?retry";
        } else {
            target = "/login?timeout";
        }
        response.sendRedirect(request.getContextPath() + target);
    }

    private static boolean signedIn() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken);
    }

    private static RequestMatcher post(String path) {
        return PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, path);
    }
}

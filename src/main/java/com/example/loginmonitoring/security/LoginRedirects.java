package com.example.loginmonitoring.security;

import com.example.loginmonitoring.service.LoginProtectionService.Denial;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

/** Small helpers shared by the login filter and the login handlers. */
public final class LoginRedirects {

    /** Session attribute: the email typed in the last login attempt (used by the login page). */
    public static final String LAST_EMAIL = "lams.lastLoginEmail";

    private LoginRedirects() {
    }

    public static String forDenial(Denial denial) {
        return switch (denial.reason()) {
            case IP_BLOCKED -> denial.permanent() ? "/login?banned" : "/login?blocked";
            default -> "/login?locked";
        };
    }

    /** Remembers the typed email so the login page can show the attempt counter for it. */
    public static void rememberEmail(HttpServletRequest request, String email) {
        HttpSession session = request.getSession(false);
        if (session != null && email != null) {
            session.setAttribute(LAST_EMAIL, email);
        }
    }
}

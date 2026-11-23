package com.example.loginmonitoring.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MvcResult;

import com.example.loginmonitoring.entity.Role;
import com.example.loginmonitoring.support.IntegrationTestBase;

class CsrfProtectionTest extends IntegrationTestBase {

    @Test
    @DisplayName("Test 14: POST /login with a missing or stale CSRF token checks nothing and asks again")
    void loginWithoutCsrfRejected() throws Exception {
        createUser("Ravi", "ravi@example.com", PASSWORD, Role.USER);

        mockMvc.perform(post("/login")
                        .param("email", "ravi@example.com")
                        .param("password", PASSWORD)
                        .with(fromIp("10.0.0.9")))
                .andExpect(redirectedUrl("/login?retry"))
                .andExpect(unauthenticated());

        mockMvc.perform(post("/login")
                        .param("email", "ravi@example.com")
                        .param("password", PASSWORD)
                        .with(csrf().useInvalidToken())
                        .with(fromIp("10.0.0.9")))
                .andExpect(redirectedUrl("/login?retry"))
                .andExpect(unauthenticated());

        assertThat(loginAttemptRepository.count()).isZero();
    }

    @Test
    @DisplayName("A stale sign-in form keeps the typed email and explains what happened")
    void staleLoginFormKeepsEmail() throws Exception {
        createUser("Ravi", "ravi@example.com", PASSWORD, Role.USER);

        // The form still carries the token of a session the server no longer has (restart, timeout)
        MvcResult result = mockMvc.perform(post("/login")
                        .param("email", "  Ravi@Example.com ")
                        .param("password", PASSWORD)
                        .param("_csrf", "token-of-a-session-the-server-lost")
                        .with(fromIp("10.0.0.9")))
                .andExpect(redirectedUrl("/login?retry"))
                .andReturn();
        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
        assertThat(session).isNotNull();

        mockMvc.perform(get("/login").param("retry", "").session(session).with(fromIp("10.0.0.9")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("value=\"ravi@example.com\"")))
                .andExpect(content().string(containsString("your password was not checked")));
    }

    @Test
    @DisplayName("Other forms with a stale token are refused; the user is told why")
    void otherFormsNeedCsrf() throws Exception {
        // Registration form from a lost session: back to the form, nothing saved
        mockMvc.perform(post("/register")
                        .param("name", "Ravi")
                        .param("email", "ravi@example.com")
                        .param("password", PASSWORD)
                        .param("confirmPassword", PASSWORD))
                .andExpect(redirectedUrl("/register?retry"));
        assertThat(userRepository.count()).isZero();
        mockMvc.perform(get("/register").param("retry", ""))
                .andExpect(content().string(containsString("nothing was saved")));

        // Signed in, but the token is old (signed in again in another tab): refused with 403
        mockMvc.perform(post("/logout").with(user("ravi@example.com")))
                .andExpect(status().isForbidden())
                .andExpect(request().attribute(CsrfFailureHandler.FORM_EXPIRED, true));

        // Sign-out after the session already ended: the user is signed out anyway
        mockMvc.perform(post("/logout").with(csrf().useInvalidToken()))
                .andExpect(redirectedUrl("/login?logout"));
    }

    @Test
    @DisplayName("An admin form sent after the session ended changes nothing and asks to sign in")
    void protectedFormAfterSessionEnded() throws Exception {
        mockMvc.perform(post("/admin/ip/block")
                        .param("ip", "203.0.113.50")
                        .param("duration", "1h")
                        .with(csrf().useInvalidToken()))
                .andExpect(redirectedUrl("/login?timeout"));
        assertThat(blockedIpRepository.count()).isZero();

        mockMvc.perform(get("/login").param("timeout", ""))
                .andExpect(content().string(containsString("Your session has ended")));
    }

    @Test
    @DisplayName("A USER opening an admin page still gets the normal 403")
    void roleDenialUnchanged() throws Exception {
        mockMvc.perform(get("/admin").with(user("ravi@example.com").roles("USER")))
                .andExpect(status().isForbidden())
                .andExpect(request().attribute(CsrfFailureHandler.FORM_EXPIRED, org.hamcrest.Matchers.nullValue()));
    }

    @Test
    @DisplayName("Rendered forms contain a hidden CSRF token")
    void formsContainCsrfToken() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(content().string(containsString("name=\"_csrf\"")));
        mockMvc.perform(get("/register"))
                .andExpect(content().string(containsString("name=\"_csrf\"")));
    }

    @Test
    @DisplayName("Security headers are sent (CSP, frame and content-type protection)")
    void securityHeaders() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Content-Security-Policy", containsString("default-src 'self'")));
    }

    @Test
    @DisplayName("Health endpoint is public and reveals no details")
    void healthEndpoint() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("\"status\":\"UP\"")))
                .andExpect(content().string(org.hamcrest.Matchers.not(containsString("components"))));
    }
}

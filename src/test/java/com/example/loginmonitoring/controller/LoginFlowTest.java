package com.example.loginmonitoring.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MvcResult;

import com.example.loginmonitoring.entity.LoginAttempt;
import com.example.loginmonitoring.entity.LoginOutcome;
import com.example.loginmonitoring.entity.Role;
import com.example.loginmonitoring.entity.User;
import com.example.loginmonitoring.support.IntegrationTestBase;

class LoginFlowTest extends IntegrationTestBase {

    private static final String IP = "192.168.1.10";

    @Test
    @DisplayName("Test 2: correct credentials log the user in and lead to /dashboard")
    void successfulLogin() throws Exception {
        createUser("Ravi Kumar", "ravi@example.com", PASSWORD, Role.USER);

        MvcResult result = login("ravi@example.com", PASSWORD, IP)
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/dashboard"))
                .andExpect(authenticated().withUsername("ravi@example.com").withRoles("USER"))
                .andReturn();

        // The dashboard opens with the same session
        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
        mockMvc.perform(get("/dashboard").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Welcome, <span>Ravi Kumar</span>")))
                .andExpect(content().string(containsString("ravi@example.com")))
                .andExpect(content().string(containsString("This is your first login.")));

        List<LoginAttempt> attempts = loginAttemptRepository.findAll();
        assertThat(attempts).hasSize(1);
        assertThat(attempts.get(0).getOutcome()).isEqualTo(LoginOutcome.SUCCESS);
        assertThat(attempts.get(0).getIpAddress()).isEqualTo(IP);
        assertThat(attempts.get(0).getAttemptedEmail()).isEqualTo("ravi@example.com");
    }

    @Test
    @DisplayName("Login email is case-insensitive; dashboard shows the previous login")
    void caseInsensitiveEmailAndPreviousLogin() throws Exception {
        createUser("Ravi Kumar", "ravi@example.com", PASSWORD, Role.USER);
        login("ravi@example.com", PASSWORD, "10.0.0.1").andExpect(redirectedUrl("/dashboard"));
        clock.advance(Duration.ofHours(1));

        MvcResult second = login("  RAVI@Example.COM ", PASSWORD, "10.0.0.2")
                .andExpect(redirectedUrl("/dashboard"))
                .andReturn();

        mockMvc.perform(get("/dashboard").session((MockHttpSession) second.getRequest().getSession(false)))
                .andExpect(content().string(containsString("(IP: <span>10.0.0.1</span>)")));
    }

    @Test
    @DisplayName("Admins are sent to /admin after login")
    void adminRedirectsToAdminDashboard() throws Exception {
        createUser("Admin", "admin@example.com", PASSWORD, Role.ADMIN);
        login("admin@example.com", PASSWORD, IP)
                .andExpect(redirectedUrl("/admin"))
                .andExpect(authenticated().withRoles("ADMIN"));
    }

    @Test
    @DisplayName("Test 3: a wrong password fails and a FAILED attempt is stored (without the password)")
    void incorrectPassword() throws Exception {
        createUser("Ravi Kumar", "ravi@example.com", PASSWORD, Role.USER);

        login("ravi@example.com", "WrongPass999", IP)
                .andExpect(redirectedUrl("/login?error"))
                .andExpect(unauthenticated());

        List<LoginAttempt> attempts = loginAttemptRepository.findAll();
        assertThat(attempts).hasSize(1);
        LoginAttempt attempt = attempts.get(0);
        assertThat(attempt.getOutcome()).isEqualTo(LoginOutcome.FAILED);
        assertThat(attempt.getIpAddress()).isEqualTo(IP);
        assertThat(attempt.getAttemptedEmail()).isEqualTo("ravi@example.com");
        assertThat(attempt.getAttemptedAt()).isNotNull();
        assertThat(attempt.toString()).doesNotContain("WrongPass999");
    }

    @Test
    @DisplayName("Unknown email shows the same generic message as a wrong password")
    void unknownEmailGenericMessage() throws Exception {
        login("nobody@example.com", PASSWORD, IP)
                .andExpect(redirectedUrl("/login?error"))
                .andExpect(unauthenticated());

        assertThat(loginAttemptRepository.countByOutcome(LoginOutcome.FAILED)).isEqualTo(1);

        mockMvc.perform(get("/login").param("error", ""))
                .andExpect(content().string(containsString("Invalid email or password.")));
    }

    @Test
    @DisplayName("Blocked message with a countdown is shown on the login page")
    void blockedMessageText() throws Exception {
        for (String email : new String[] {"a@example.com", "b@example.com", "c@example.com", "d@example.com"}) {
            login(email, "WrongPass999", IP);
        }
        mockMvc.perform(get("/login").param("blocked", "").with(fromIp(IP)))
                .andExpect(content().string(containsString("Your IP address has been temporarily blocked.")))
                .andExpect(content().string(containsString("data-seconds=\"900\"")))
                .andExpect(content().string(containsString("15:00")));
    }

    @Test
    @DisplayName("Missing email or password is not counted as a failed attempt")
    void malformedSubmissionNotCounted() throws Exception {
        createUser("Ravi Kumar", "ravi@example.com", PASSWORD, Role.USER);

        login("ravi@example.com", "", IP).andExpect(redirectedUrl("/login?missing"));
        login("", PASSWORD, IP).andExpect(redirectedUrl("/login?missing"));
        mockMvc.perform(post("/login").with(csrf()).with(fromIp(IP)))
                .andExpect(redirectedUrl("/login?missing"));

        assertThat(loginAttemptRepository.count()).isZero();
    }

    @Test
    @DisplayName("Disabled account: 'disabled' only with the right password, generic error otherwise")
    void disabledAccount() throws Exception {
        User user = createUser("Old User", "old@example.com", PASSWORD, Role.USER);
        user.setEnabled(false);
        userRepository.save(user);

        login("old@example.com", "WrongPass999", IP)
                .andExpect(redirectedUrl("/login?error"))
                .andExpect(unauthenticated());
        login("old@example.com", PASSWORD, IP)
                .andExpect(redirectedUrl("/login?disabled"))
                .andExpect(unauthenticated());

        assertThat(loginAttemptRepository.countByOutcome(LoginOutcome.FAILED)).isEqualTo(2);
    }

    @Test
    @DisplayName("Session id changes after login (session fixation protection)")
    void sessionIdChangesOnLogin() throws Exception {
        createUser("Ravi Kumar", "ravi@example.com", PASSWORD, Role.USER);
        MockHttpSession session = new MockHttpSession();
        String idBeforeLogin = session.getId();

        MvcResult result = mockMvc.perform(post("/login")
                        .param("email", "ravi@example.com")
                        .param("password", PASSWORD)
                        .session(session)
                        .with(request -> {
                            // like a browser sending its JSESSIONID cookie
                            request.setRequestedSessionId(idBeforeLogin);
                            return request;
                        })
                        .with(csrf())
                        .with(fromIp(IP)))
                .andExpect(authenticated())
                .andReturn();

        assertThat(result.getRequest().getSession(false).getId()).isNotEqualTo(idBeforeLogin);
    }

    @Test
    @DisplayName("Logout invalidates the session")
    void logoutInvalidatesSession() throws Exception {
        createUser("Ravi Kumar", "ravi@example.com", PASSWORD, Role.USER);
        MvcResult result = login("ravi@example.com", PASSWORD, IP).andReturn();
        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);

        mockMvc.perform(post("/logout").session(session).with(csrf()))
                .andExpect(redirectedUrl("/login?logout"))
                .andExpect(unauthenticated());

        assertThat(session.isInvalid()).isTrue();
        mockMvc.perform(get("/dashboard").session(new MockHttpSession()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login"));
    }

    @Test
    @DisplayName("Protected pages redirect anonymous visitors to the login page")
    void anonymousRedirectedToLogin() throws Exception {
        mockMvc.perform(get("/dashboard")).andExpect(redirectedUrl("/login"));
        mockMvc.perform(get("/admin")).andExpect(redirectedUrl("/login"));
    }

    @Test
    @DisplayName("A very long password at login fails normally (no server error)")
    void veryLongPasswordAtLogin() throws Exception {
        createUser("Ravi Kumar", "ravi@example.com", PASSWORD, Role.USER);
        login("ravi@example.com", "A1".repeat(100), IP)
                .andExpect(redirectedUrl("/login?error"))
                .andExpect(unauthenticated());
        assertThat(loginAttemptRepository.countByOutcome(LoginOutcome.FAILED)).isEqualTo(1);
    }
}

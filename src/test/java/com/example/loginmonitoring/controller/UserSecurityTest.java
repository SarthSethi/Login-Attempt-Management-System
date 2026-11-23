package com.example.loginmonitoring.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.OptionalLong;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import com.example.loginmonitoring.entity.AlertType;
import com.example.loginmonitoring.entity.BlockSource;
import com.example.loginmonitoring.entity.BlockedIp;
import com.example.loginmonitoring.entity.LoginAttempt;
import com.example.loginmonitoring.entity.LoginOutcome;
import com.example.loginmonitoring.entity.RiskFlag;
import com.example.loginmonitoring.entity.Role;
import com.example.loginmonitoring.entity.SecurityAlert;
import com.example.loginmonitoring.service.intel.BreachedPasswordService;
import com.example.loginmonitoring.support.IntegrationTestBase;

/** The account owner's side: activity, risk flags, sessions, "This wasn't me", password change. */
class UserSecurityTest extends IntegrationTestBase {

    private static final String HOME_IP = "10.0.0.1";
    private static final String OTHER_IP = "10.0.0.2";

    @MockitoBean
    private BreachedPasswordService breachedPasswordService;

    @BeforeEach
    void setUp() {
        createUser("Ravi Kumar", "ravi@example.com", PASSWORD, Role.USER);
        when(breachedPasswordService.breachCount(anyString())).thenReturn(OptionalLong.of(0));
    }

    private MockHttpSession loginSession(String ip, String userAgent) throws Exception {
        return (MockHttpSession) login("ravi@example.com", PASSWORD, ip, userAgent)
                .andExpect(redirectedUrl("/dashboard"))
                .andReturn().getRequest().getSession(false);
    }

    private LoginAttempt latestSuccess() {
        return loginAttemptRepository.findAll().stream()
                .filter(a -> a.getOutcome() == LoginOutcome.SUCCESS)
                .reduce((first, second) -> second).orElseThrow();
    }

    @Test
    @DisplayName("Device is read from the User-Agent and stored with the attempt")
    void deviceIsRecorded() throws Exception {
        loginSession(HOME_IP, CHROME_WINDOWS);
        LoginAttempt attempt = latestSuccess();
        assertThat(attempt.getBrowser()).isEqualTo("Chrome");
        assertThat(attempt.getOs()).isEqualTo("Windows 10/11");
        assertThat(attempt.getDeviceType()).isEqualTo("Desktop");
        assertThat(attempt.getRiskFlagList()).isEmpty();
    }

    @Test
    @DisplayName("Dashboard warns about failed attempts since the last login and lists them")
    void failedAttemptsBanner() throws Exception {
        loginSession(HOME_IP, CHROME_WINDOWS);
        clock.advance(Duration.ofHours(2));
        login("ravi@example.com", "Wrong1111", "10.6.6.6");
        login("ravi@example.com", "Wrong2222", "10.6.6.6");
        clock.advance(Duration.ofHours(2));

        MockHttpSession session = loginSession(HOME_IP, CHROME_WINDOWS);
        mockMvc.perform(get("/dashboard").session(session))
                .andExpect(status().isOk())
                .andExpect(model().attribute("failedSinceLastLogin", 2L))
                .andExpect(model().attribute("activity", hasSize(4)))
                .andExpect(content().string(containsString("failed sign-in attempt(s) on your account since your last login")))
                .andExpect(content().string(containsString("10.6.6.6")))
                .andExpect(content().string(containsString("THIS SESSION")));
    }

    @Test
    @DisplayName("Success right after several failures is flagged and raises an alert")
    void successAfterFailuresIsRisky() throws Exception {
        for (int i = 0; i < 3; i++) {
            login("ravi@example.com", "Wrong1111", OTHER_IP);
        }
        loginSession(OTHER_IP, CHROME_WINDOWS);

        assertThat(latestSuccess().getRiskFlagList()).containsExactly(RiskFlag.AFTER_FAILURES);
        assertThat(alertRepository.findAll()).singleElement().satisfies(alert -> {
            assertThat(alert.getType()).isEqualTo(AlertType.SUSPICIOUS_LOGIN);
            assertThat(alert.getMessage()).contains("ravi@example.com").contains("3 failed attempts");
        });
    }

    @Test
    @DisplayName("New device and automated clients are flagged")
    void newDeviceAndScriptFlags() throws Exception {
        loginSession(HOME_IP, CHROME_WINDOWS);
        loginSession(HOME_IP, FIREFOX_LINUX);
        assertThat(latestSuccess().getRiskFlagList()).containsExactly(RiskFlag.NEW_DEVICE);
        assertThat(alertRepository.count()).as("a new device alone is not alarming").isZero();

        loginSession(HOME_IP, "curl/8.5.0");
        assertThat(latestSuccess().getRiskFlagList()).contains(RiskFlag.AUTOMATED_CLIENT, RiskFlag.NEW_DEVICE);
        assertThat(alertRepository.findAll()).extracting(SecurityAlert::getType).containsExactly(AlertType.SUSPICIOUS_LOGIN);
    }

    @Test
    @DisplayName("Active sessions are listed and other devices can be signed out")
    void signOutOtherDevices() throws Exception {
        MockHttpSession laptop = loginSession(HOME_IP, CHROME_WINDOWS);
        MockHttpSession phone = loginSession(OTHER_IP, FIREFOX_LINUX);

        mockMvc.perform(get("/dashboard").session(phone))
                .andExpect(model().attribute("sessions", hasSize(2)))
                .andExpect(content().string(containsString("THIS DEVICE")))
                .andExpect(content().string(not(containsString("value=\"" + laptop.getId() + "\""))));

        mockMvc.perform(post("/account/sessions/signout-others").session(phone).with(csrf()))
                .andExpect(redirectedUrl("/dashboard"));
        mockMvc.perform(get("/dashboard").session(laptop)).andExpect(redirectedUrl("/login?expired"));
        mockMvc.perform(get("/dashboard").session(phone)).andExpect(status().isOk());
    }

    @Test
    @DisplayName("'This wasn't me' blocks the IP, signs out other sessions, alerts the admin")
    void reportLogin() throws Exception {
        MockHttpSession attacker = loginSession(OTHER_IP, FIREFOX_LINUX);
        long attackerLoginId = latestSuccess().getId();
        clock.advance(Duration.ofMinutes(30));
        MockHttpSession owner = loginSession(HOME_IP, CHROME_WINDOWS);

        mockMvc.perform(post("/account/report/{id}", attackerLoginId).session(owner).with(csrf()).with(fromIp(HOME_IP)))
                .andExpect(redirectedUrl("/account/password"));

        BlockedIp block = blockedIpRepository.findAll().get(0);
        assertThat(block.getIpAddress()).isEqualTo(OTHER_IP);
        assertThat(block.getSource()).isEqualTo(BlockSource.USER_REPORT);
        assertThat(block.getExpiresAt()).isEqualTo(LocalDateTime.now(clock).plusHours(24));
        assertThat(loginAttemptRepository.findById(attackerLoginId).orElseThrow().isReported()).isTrue();
        assertThat(alertRepository.findAll()).extracting(SecurityAlert::getType).containsExactly(AlertType.USER_REPORTED);

        mockMvc.perform(get("/dashboard").session(attacker)).andExpect(redirectedUrl("/login?expired"));
        login("ravi@example.com", PASSWORD, OTHER_IP).andExpect(redirectedUrl("/login?blocked"));
    }

    @Test
    @DisplayName("Users cannot report their current login or somebody else's login")
    void reportSafetyChecks() throws Exception {
        createUser("Other", "other@example.com", PASSWORD, Role.USER);
        login("other@example.com", PASSWORD, OTHER_IP);
        long othersLogin = latestSuccess().getId();

        MockHttpSession session = loginSession(HOME_IP, CHROME_WINDOWS);
        long myLogin = latestSuccess().getId();

        mockMvc.perform(post("/account/report/{id}", othersLogin).session(session).with(csrf()))
                .andExpect(redirectedUrl("/dashboard"));
        mockMvc.perform(post("/account/report/{id}", myLogin).session(session).with(csrf()))
                .andExpect(redirectedUrl("/dashboard"));
        assertThat(blockedIpRepository.count()).isZero();
    }

    @Test
    @DisplayName("Change password: wrong current password is rejected; a good one changes the hash")
    void changePassword() throws Exception {
        MockHttpSession session = loginSession(HOME_IP, CHROME_WINDOWS);
        mockMvc.perform(get("/account/password").session(session)).andExpect(status().isOk());

        mockMvc.perform(post("/account/password").session(session).with(csrf())
                        .param("currentPassword", "nope12345").param("newPassword", "NewSecret456")
                        .param("confirmPassword", "NewSecret456"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Your current password is not correct.")));

        mockMvc.perform(post("/account/password").session(session).with(csrf())
                        .param("currentPassword", PASSWORD).param("newPassword", "NewSecret456")
                        .param("confirmPassword", "NewSecret456"))
                .andExpect(redirectedUrl("/dashboard"));
        String hash = userRepository.findByEmail("ravi@example.com").orElseThrow().getPasswordHash();
        assertThat(passwordEncoder.matches("NewSecret456", hash)).isTrue();
    }

    @Test
    @DisplayName("Passwords found in data breaches are rejected at registration and password change")
    void breachedPasswordsRejected() throws Exception {
        when(breachedPasswordService.breachCount("Password123")).thenReturn(OptionalLong.of(123456));

        mockMvc.perform(post("/register").with(csrf())
                        .param("name", "New").param("email", "new@example.com")
                        .param("password", "Password123").param("confirmPassword", "Password123"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("123,456 known data breaches")));
        assertThat(userRepository.findByEmail("new@example.com")).isEmpty();

        MockHttpSession session = loginSession(HOME_IP, CHROME_WINDOWS);
        mockMvc.perform(post("/account/password").session(session).with(csrf())
                        .param("currentPassword", PASSWORD).param("newPassword", "Password123")
                        .param("confirmPassword", "Password123"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("known data breaches")));
    }

    @Test
    @DisplayName("If the breach service is down, registration still works")
    void breachServiceDown() throws Exception {
        when(breachedPasswordService.breachCount(anyString())).thenReturn(OptionalLong.empty());
        mockMvc.perform(post("/register").with(csrf())
                        .param("name", "New").param("email", "new@example.com")
                        .param("password", "Password123").param("confirmPassword", "Password123"))
                .andExpect(redirectedUrl("/login?registered"));
    }
}

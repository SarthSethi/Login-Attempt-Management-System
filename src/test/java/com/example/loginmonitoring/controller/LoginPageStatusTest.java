package com.example.loginmonitoring.controller;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;

import java.time.Duration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.ResultActions;

import com.example.loginmonitoring.entity.Role;
import com.example.loginmonitoring.service.LoginStatus;
import com.example.loginmonitoring.support.IntegrationTestBase;

/**
 * The login page shows the real attempt counter, read from the database. These tests use one
 * browser session, like a real visitor who types a wrong password and then refreshes the page.
 */
class LoginPageStatusTest extends IntegrationTestBase {

    private static final String IP = "192.168.5.5";

    private MockHttpSession session;

    @BeforeEach
    void setUp() {
        createUser("Asha", "asha@example.com", PASSWORD, Role.USER);
        session = new MockHttpSession();
    }

    private ResultActions submit(String email, String password) throws Exception {
        return mockMvc.perform(post("/login").session(session).param("email", email).param("password", password)
                .with(csrf()).with(fromIp(IP)));
    }

    private ResultActions loginPage(String query) throws Exception {
        return mockMvc.perform(get("/login" + query).session(session).with(fromIp(IP)));
    }

    @Test
    @DisplayName("After each wrong password the page shows 'attempt N of 5' - and a refresh shows the same")
    void counterSurvivesRefresh() throws Exception {
        submit("asha@example.com", "Wrong1111").andExpect(redirectedUrl("/login?error"));
        loginPage("?error")
                .andExpect(content().string(containsString("Invalid email or password.")))
                .andExpect(content().string(containsString("Attempt <b>1</b> of <span>5</span>")))
                .andExpect(content().string(containsString("value=\"asha@example.com\"")));

        submit("asha@example.com", "Wrong2222");
        submit("asha@example.com", "Wrong3333");
        // Refresh twice, also without the ?error in the address: the counter does not reset
        loginPage("?error").andExpect(content().string(containsString("Attempt <b>3</b> of <span>5</span>")));
        loginPage("").andExpect(content().string(containsString("Attempt <b>3</b> of <span>5</span>")))
                .andExpect(content().string(containsString("<span>2</span>\n                    left before")));
    }

    @Test
    @DisplayName("After 5 wrong passwords the page shows the lock with a countdown, also after a refresh")
    void lockedWithCountdown() throws Exception {
        for (int i = 0; i < 5; i++) {
            submit("asha@example.com", "Wrong" + i + "pass");
        }
        loginPage("?locked")
                .andExpect(content().string(containsString("is paused on this network.")))
                .andExpect(content().string(containsString("data-seconds=\"900\"")));

        clock.advance(Duration.ofMinutes(5));
        loginPage("").andExpect(content().string(containsString("data-seconds=\"600\"")))
                .andExpect(content().string(containsString("10:00")));

        clock.advance(Duration.ofMinutes(10));
        loginPage("?locked").andExpect(content().string(containsString("The block has ended.")));
    }

    @Test
    @DisplayName("When the IP is blocked the sign-in button is disabled")
    void blockedIpDisablesButton() throws Exception {
        for (String email : new String[] {"a@example.com", "b@example.com", "c@example.com", "d@example.com"}) {
            submit(email, "Wrong1111");
        }
        loginPage("?blocked")
                .andExpect(content().string(containsString("Your IP address has been temporarily blocked.")))
                .andExpect(content().string(containsString("id=\"login-button\" disabled")));
    }

    @Test
    @DisplayName("The network warning appears before the IP is blocked")
    void networkWarning() throws Exception {
        submit("a@example.com", "Wrong1111");
        loginPage("").andExpect(content().string(not(containsString("Warning for your network"))));
        submit("b@example.com", "Wrong1111");
        submit("c@example.com", "Wrong1111");
        loginPage("?error").andExpect(content().string(containsString("Warning for your network")))
                .andExpect(content().string(containsString("(<span>3</span> different accounts)")));
    }

    @Test
    @DisplayName("'Use a different email' forgets the typed email; a success clears the counter display")
    void clearAndSuccess() throws Exception {
        submit("asha@example.com", "Wrong1111");
        mockMvc.perform(get("/login").param("clear", "").session(session)).andExpect(redirectedUrl("/login"));
        loginPage("").andExpect(content().string(not(containsString("Attempt <b>"))));

        submit("asha@example.com", PASSWORD).andExpect(redirectedUrl("/dashboard"));
        LoginStatus status = (LoginStatus) mockMvc.perform(get("/login").session(new MockHttpSession()).with(fromIp(IP)))
                .andReturn().getModelAndView().getModel().get("status");
        org.assertj.core.api.Assertions.assertThat(status.state()).isEqualTo(LoginStatus.State.CLEAR);
    }
}

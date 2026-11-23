package com.example.loginmonitoring.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MvcResult;

import com.example.loginmonitoring.dto.BlockedIpView;
import com.example.loginmonitoring.entity.LoginAttempt;
import com.example.loginmonitoring.entity.LoginOutcome;
import com.example.loginmonitoring.entity.Role;
import com.example.loginmonitoring.support.IntegrationTestBase;

class AdminDashboardTest extends IntegrationTestBase {

    private static final List<String> ADMIN_PAGES = List.of("/admin", "/admin?range=7d", "/admin/attempts",
            "/admin/protection", "/admin/alerts", "/admin/alerts?show=all", "/admin/users", "/admin/simulator",
            "/admin/audit", "/admin/ip?ip=10.0.0.3", "/admin/api/feed", "/admin/attempts.csv");

    @BeforeEach
    void createUsers() {
        createUser("Alice", "alice@example.com", PASSWORD, Role.USER);
        createUser("Bob", "bob@example.com", PASSWORD, Role.USER);
    }

    @Test
    @DisplayName("A normal USER gets 403 on every admin page")
    void userCannotOpenAdmin() throws Exception {
        MvcResult result = login("alice@example.com", PASSWORD, "10.0.0.1").andReturn();
        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);

        for (String page : ADMIN_PAGES) {
            mockMvc.perform(get(page).session(session)).andExpect(status().isForbidden());
        }
        mockMvc.perform(get("/admin").with(user("alice@example.com").roles("USER")))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Every admin page opens for an administrator (with and without data)")
    void allAdminPagesRender() throws Exception {
        for (String page : ADMIN_PAGES) {
            mockMvc.perform(get(page).with(admin())).andExpect(status().isOk());
        }
        login("alice@example.com", PASSWORD, "10.0.0.1", CHROME_WINDOWS);
        login("alice@example.com", "Wrong1111", "10.0.0.3", FIREFOX_LINUX);
        login("ghost@example.com", "Wrong1111", "10.0.0.3");
        for (String page : ADMIN_PAGES) {
            mockMvc.perform(get(page).with(admin())).andExpect(status().isOk());
        }
    }

    @Test
    @DisplayName("Overview shows real database counts, the feed and active blocks")
    void overviewShowsRealData() throws Exception {
        login("alice@example.com", PASSWORD, "10.0.0.1");
        login("bob@example.com", PASSWORD, "10.0.0.2");
        login("alice@example.com", "Wrong1111", "10.0.0.3");
        login("bob@example.com", "Wrong1111", "10.0.0.3");
        login("ghost@example.com", "Wrong1111", "10.0.0.3");

        mockMvc.perform(get("/admin").with(admin()))
                .andExpect(status().isOk())
                .andExpect(model().attribute("totalAttempts", 5L))
                .andExpect(model().attribute("failedAttempts", 3L))
                .andExpect(model().attribute("successfulAttempts", 2L))
                .andExpect(model().attribute("attempts24h", 5L))
                .andExpect(model().attribute("activeBlockedIps", 0L))
                .andExpect(model().attribute("feed", hasSize(5)))
                .andExpect(content().string(containsString("ghost@example.com")))
                .andExpect(content().string(containsString("10.0.0.3")))
                .andExpect(content().string(containsString("Private network")))
                .andExpect(content().string(containsString("No IP addresses are blocked.")));

        // A 4th account from 10.0.0.3 -> credential stuffing -> blocked
        login("carol@example.com", "Wrong1111", "10.0.0.3");
        login("alice@example.com", PASSWORD, "10.0.0.3"); // rejected as BLOCKED

        MvcResult result = mockMvc.perform(get("/admin").with(admin()))
                .andExpect(model().attribute("totalAttempts", 7L))
                .andExpect(model().attribute("failedAttempts", 4L))
                .andExpect(model().attribute("blockedRequests", 1L))
                .andExpect(model().attribute("activeBlockedIps", 1L))
                .andExpect(model().attribute("openAlertCount", 1L))
                .andExpect(content().string(containsString("Credential stuffing")))
                .andExpect(content().string(containsString("15 min 00 s")))
                .andReturn();

        @SuppressWarnings("unchecked")
        List<LoginAttempt> feed = (List<LoginAttempt>) result.getModelAndView().getModel().get("feed");
        assertThat(feed.get(0).getOutcome()).isEqualTo(LoginOutcome.BLOCKED);

        // After 15 minutes the block is no longer active
        clock.advance(Duration.ofMinutes(15));
        mockMvc.perform(get("/admin").with(admin())).andExpect(model().attribute("activeBlockedIps", 0L));
        MvcResult protection = mockMvc.perform(get("/admin/protection").with(admin()))
                .andExpect(content().string(containsString("EXPIRED"))).andReturn();
        @SuppressWarnings("unchecked")
        List<BlockedIpView> history = (List<BlockedIpView>) protection.getModelAndView().getModel().get("blockHistory");
        assertThat(history).singleElement().satisfies(b -> assertThat(b.status()).isEqualTo("EXPIRED"));
    }

    @Test
    @DisplayName("Live feed API returns only newer attempts")
    void feedApi() throws Exception {
        login("alice@example.com", PASSWORD, "10.0.0.1", CHROME_WINDOWS);
        long firstId = loginAttemptRepository.findAll().get(0).getId();
        login("bob@example.com", "Wrong1111", "10.0.0.2");

        mockMvc.perform(get("/admin/api/feed").param("after", String.valueOf(firstId)).with(admin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items", hasSize(1)))
                .andExpect(jsonPath("$.items[0].email").value("bob@example.com"))
                .andExpect(jsonPath("$.items[0].outcome").value("FAILED"))
                .andExpect(jsonPath("$.items[0].reason").value("Wrong password"));
        mockMvc.perform(get("/admin/api/feed").param("after", "0").with(admin()))
                .andExpect(jsonPath("$.items", hasSize(2)))
                .andExpect(jsonPath("$.items[1].device").value("Chrome on Windows 10/11"));
    }

    @Test
    @DisplayName("Attempt log: status, IP and email filters and paging work")
    void filterAndSearch() throws Exception {
        login("alice@example.com", PASSWORD, "10.0.0.1");
        login("alice@example.com", "Wrong1111", "10.0.0.1");
        login("bob@example.com", "Wrong1111", "172.16.5.9");

        mockMvc.perform(get("/admin/attempts").with(admin()))
                .andExpect(model().attribute("attempts", hasSize(3)));
        mockMvc.perform(get("/admin/attempts").param("status", "FAILED").with(admin()))
                .andExpect(model().attribute("attempts", hasSize(2)))
                .andExpect(model().attribute("statusFilter", "FAILED"));
        mockMvc.perform(get("/admin/attempts").param("ip", "172.16").with(admin()))
                .andExpect(model().attribute("attempts", hasSize(1)))
                .andExpect(content().string(containsString("172.16.5.9")))
                .andExpect(content().string(not(containsString(">10.0.0.1<"))));
        mockMvc.perform(get("/admin/attempts").param("email", "BOB@").with(admin()))
                .andExpect(model().attribute("attempts", hasSize(1)));
        mockMvc.perform(get("/admin/attempts").param("status", "SUCCESS").param("ip", "10.0.0.1").with(admin()))
                .andExpect(model().attribute("attempts", hasSize(1)));
        // Unknown status value is ignored instead of causing an error
        mockMvc.perform(get("/admin/attempts").param("status", "NOPE").with(admin()))
                .andExpect(status().isOk())
                .andExpect(model().attribute("attempts", hasSize(3)));
        // Silly page numbers do not break anything
        mockMvc.perform(get("/admin/attempts").param("page", "-5").with(admin())).andExpect(status().isOk());
    }

    @Test
    @DisplayName("CSV export contains the rows and defuses spreadsheet formulas")
    void csvExport() throws Exception {
        login("=cmd|' /C calc'!A0@example.com", "Wrong1111", "10.0.0.9");
        login("alice@example.com", PASSWORD, "10.0.0.1");

        String csv = mockMvc.perform(get("/admin/attempts.csv").with(admin()))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", containsString("login-attempts.csv")))
                .andReturn().getResponse().getContentAsString();
        assertThat(csv).contains("id,time_utc,ip_address,email,outcome");
        assertThat(csv).contains("alice@example.com").contains("SUCCESS");
        assertThat(csv).contains("'=cmd|' /c calc'!a0@example.com");
        assertThat(csv).doesNotContain(",=cmd");
    }

    @Test
    @DisplayName("IP page shows the accounts tried and the block history; invalid IPs are rejected")
    void ipPage() throws Exception {
        login("alice@example.com", "Wrong1111", "10.0.0.3");
        login("bob@example.com", "Wrong1111", "10.0.0.3");

        mockMvc.perform(get("/admin/ip").param("ip", "10.0.0.3").with(admin()))
                .andExpect(status().isOk())
                .andExpect(model().attribute("failed", 2L))
                .andExpect(model().attribute("emailsTried", hasSize(2)))
                .andExpect(content().string(containsString("bob@example.com")));
        mockMvc.perform(get("/admin/ip").param("ip", "<script>").with(admin()))
                .andExpect(status().isOk())
                .andExpect(model().attribute("invalidIp", "<script>"))
                .andExpect(content().string(not(containsString("<script>"))));
    }

    @Test
    @DisplayName("Admin pages never show password hashes")
    void noPasswordHashesOnPages() throws Exception {
        String hash = userRepository.findByEmail("alice@example.com").orElseThrow().getPasswordHash();
        MvcResult result = login("alice@example.com", PASSWORD, "10.0.0.1").andReturn();

        for (String page : List.of("/admin", "/admin/users", "/admin/attempts")) {
            mockMvc.perform(get(page).with(admin()))
                    .andExpect(content().string(not(containsString(hash))))
                    .andExpect(content().string(not(containsString("$2a$"))));
        }
        mockMvc.perform(get("/dashboard").session((MockHttpSession) result.getRequest().getSession(false)))
                .andExpect(content().string(not(containsString(hash))))
                .andExpect(content().string(not(containsString("$2a$"))));
    }
}

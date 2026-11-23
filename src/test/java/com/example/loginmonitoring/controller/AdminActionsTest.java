package com.example.loginmonitoring.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;
import java.time.LocalDateTime;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;

import com.example.loginmonitoring.entity.AdminAction;
import com.example.loginmonitoring.entity.BlockSource;
import com.example.loginmonitoring.entity.BlockedIp;
import com.example.loginmonitoring.entity.Role;
import com.example.loginmonitoring.entity.User;
import com.example.loginmonitoring.service.BlockedIpService;
import com.example.loginmonitoring.support.IntegrationTestBase;

class AdminActionsTest extends IntegrationTestBase {

    private static final String ADMIN_IP = "10.9.9.9";

    @Autowired
    private BlockedIpService blockedIpService;

    @Test
    @DisplayName("Admin can block an IP for 24 hours and unblock it again; both are audited")
    void blockAndUnblock() throws Exception {
        mockMvc.perform(post("/admin/ip/block").param("ip", "203.0.113.9").param("duration", "24h")
                        .param("reason", "scanner").with(admin()).with(csrf()).with(fromIp(ADMIN_IP)))
                .andExpect(redirectedUrl("/admin/protection"));

        BlockedIp block = blockedIpService.findActiveBlock("203.0.113.9").orElseThrow();
        assertThat(block.getSource()).isEqualTo(BlockSource.MANUAL);
        assertThat(block.getCreatedBy()).isEqualTo("admin@example.com");
        assertThat(block.getExpiresAt()).isEqualTo(LocalDateTime.now(clock).plusHours(24));
        login("someone@example.com", PASSWORD, "203.0.113.9").andExpect(redirectedUrl("/login?blocked"));

        mockMvc.perform(post("/admin/ip/unblock").param("ip", "203.0.113.9").param("back", "ip")
                        .with(admin()).with(csrf()).with(fromIp(ADMIN_IP)))
                .andExpect(redirectedUrl("/admin/ip?ip=203.0.113.9"));
        assertThat(blockedIpService.isBlocked("203.0.113.9")).isFalse();
        assertThat(blockedIpRepository.findAll().get(0).getLiftedBy()).isEqualTo("admin@example.com");

        assertThat(adminActionRepository.findAll()).extracting(AdminAction::getAction)
                .containsExactlyInAnyOrder("BLOCK_IP", "UNBLOCK_IP");
    }

    @Test
    @DisplayName("Permanent ban lasts forever")
    void permanentBan() throws Exception {
        mockMvc.perform(post("/admin/ip/block").param("ip", "203.0.113.10").param("duration", "permanent")
                .with(admin()).with(csrf()).with(fromIp(ADMIN_IP)));
        clock.advance(Duration.ofDays(3650));
        assertThat(blockedIpService.isBlocked("203.0.113.10")).isTrue();
        login("someone@example.com", PASSWORD, "203.0.113.10").andExpect(redirectedUrl("/login?banned"));
    }

    @Test
    @DisplayName("Admin cannot block their own IP, a trusted IP, or something that is not an IP")
    void blockSafetyChecks() throws Exception {
        mockMvc.perform(post("/admin/ip/block").param("ip", ADMIN_IP).param("duration", "1h")
                        .with(admin()).with(csrf()).with(fromIp(ADMIN_IP)))
                .andExpect(flash().attributeExists("error"));
        mockMvc.perform(post("/admin/ip/block").param("ip", "evil.example.com").param("duration", "1h")
                        .with(admin()).with(csrf()).with(fromIp(ADMIN_IP)))
                .andExpect(flash().attribute("error", "Not a valid IP address."));
        allowlistService.add("198.51.100.0/24", "office", "admin@example.com");
        mockMvc.perform(post("/admin/ip/block").param("ip", "198.51.100.4").param("duration", "1h")
                        .with(admin()).with(csrf()).with(fromIp(ADMIN_IP)))
                .andExpect(flash().attributeExists("error"));
        assertThat(blockedIpRepository.count()).isZero();
    }

    @Test
    @DisplayName("Allow-list accepts IPs and CIDR ranges and rejects anything else")
    void allowlist() throws Exception {
        mockMvc.perform(post("/admin/allowlist/add").param("cidr", " 192.168.1.0/24 ").param("note", "College")
                        .with(admin()).with(csrf()))
                .andExpect(redirectedUrl("/admin/protection"));
        mockMvc.perform(post("/admin/allowlist/add").param("cidr", "not-an-ip/99").with(admin()).with(csrf()))
                .andExpect(flash().attributeExists("error"));
        assertThat(allowlistRepository.findAll()).singleElement()
                .satisfies(e -> assertThat(e.getCidr()).isEqualTo("192.168.1.0/24"));
        assertThat(allowlistService.isAllowlisted("192.168.1.77")).isTrue();
        assertThat(allowlistService.isAllowlisted("192.168.2.1")).isFalse();

        long id = allowlistRepository.findAll().get(0).getId();
        mockMvc.perform(post("/admin/allowlist/{id}/delete", id).with(admin()).with(csrf()));
        assertThat(allowlistService.isAllowlisted("192.168.1.77")).isFalse();
    }

    @Test
    @DisplayName("Disabling a user signs them out at once; enabling lets them back in")
    void disableAndEnableUser() throws Exception {
        User user = createUser("Alice", "alice@example.com", PASSWORD, Role.USER);
        MockHttpSession session = (MockHttpSession) login("alice@example.com", PASSWORD, "10.0.0.1")
                .andReturn().getRequest().getSession(false);
        mockMvc.perform(get("/dashboard").session(session)).andExpect(status().isOk());

        mockMvc.perform(post("/admin/users/{id}/disable", user.getId()).with(admin()).with(csrf()))
                .andExpect(redirectedUrl("/admin/users"));
        assertThat(userRepository.findById(user.getId()).orElseThrow().isEnabled()).isFalse();
        mockMvc.perform(get("/dashboard").session(session)).andExpect(redirectedUrl("/login?expired"));
        login("alice@example.com", PASSWORD, "10.0.0.1").andExpect(redirectedUrl("/login?disabled"));

        mockMvc.perform(post("/admin/users/{id}/enable", user.getId()).with(admin()).with(csrf()));
        login("alice@example.com", PASSWORD, "10.0.0.1").andExpect(redirectedUrl("/dashboard"));
    }

    @Test
    @DisplayName("Admin cannot disable their own account")
    void cannotDisableSelf() throws Exception {
        User admin = createUser("Admin", "admin@example.com", PASSWORD, Role.ADMIN);
        mockMvc.perform(post("/admin/users/{id}/disable", admin.getId()).with(admin()).with(csrf()))
                .andExpect(flash().attribute("error", "You cannot disable your own account."));
        assertThat(userRepository.findById(admin.getId()).orElseThrow().isEnabled()).isTrue();
    }

    @Test
    @DisplayName("Unlock lifts account locks; alerts can be marked as handled")
    void unlockAndAcknowledge() throws Exception {
        User user = createUser("Alice", "alice@example.com", PASSWORD, Role.USER);
        for (int i = 0; i < 5; i++) {
            login("alice@example.com", "Wrong1111", "10.0.0.5");
        }
        login("alice@example.com", PASSWORD, "10.0.0.5").andExpect(redirectedUrl("/login?locked"));

        mockMvc.perform(post("/admin/users/{id}/unlock", user.getId()).with(admin()).with(csrf()));
        login("alice@example.com", PASSWORD, "10.0.0.5").andExpect(redirectedUrl("/dashboard"));

        // Brute-force alert + "successful login right after 5 failures" alert
        assertThat(alertRepository.countByAcknowledgedFalse()).isEqualTo(2);
        mockMvc.perform(post("/admin/alerts/ack-all").with(admin()).with(csrf()));
        assertThat(alertRepository.countByAcknowledgedFalse()).isZero();
    }

    @Test
    @DisplayName("Admin actions need the CSRF token")
    void actionsNeedCsrf() throws Exception {
        mockMvc.perform(post("/admin/ip/block").param("ip", "203.0.113.9").param("duration", "24h").with(admin()))
                .andExpect(status().isForbidden());
        assertThat(blockedIpRepository.count()).isZero();
    }
}

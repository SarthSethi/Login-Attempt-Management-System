package com.example.loginmonitoring.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.example.loginmonitoring.entity.LoginOutcome;
import com.example.loginmonitoring.entity.Role;
import com.example.loginmonitoring.support.IntegrationTestBase;

/**
 * Harmless SQL-injection-style inputs must be treated as plain text.
 * All database access goes through Spring Data JPA with bound parameters.
 */
class SqlInjectionTest extends IntegrationTestBase {

    private static final String IP = "10.20.30.40";

    @Test
    @DisplayName("Test 11: SQL-injection-style login input fails and the database stays intact")
    void sqlInjectionStyleLogin() throws Exception {
        createUser("Victim", "victim@example.com", PASSWORD, Role.USER);

        login("' OR '1'='1' -- ", "' OR '1'='1", IP)
                .andExpect(redirectedUrl("/login?error"))
                .andExpect(unauthenticated());

        login("victim@example.com' --", "anything", IP)
                .andExpect(redirectedUrl("/login?error"))
                .andExpect(unauthenticated());

        login("x@example.com'; DROP TABLE users; --", "x", IP)
                .andExpect(redirectedUrl("/login?error"))
                .andExpect(unauthenticated());

        // users table still exists and still has exactly one row
        assertThat(userRepository.count()).isEqualTo(1);
        assertThat(userRepository.findByEmail("victim@example.com")).isPresent();

        // The injected text was stored literally as the attempted email
        assertThat(loginAttemptRepository.countByOutcome(LoginOutcome.FAILED)).isEqualTo(3);
        assertThat(loginAttemptRepository.findAll())
                .extracting(a -> a.getAttemptedEmail())
                .contains("' or '1'='1' --", "x@example.com'; drop table users; --");
    }

    @Test
    @DisplayName("SQL-like text in the registration name is stored as plain text")
    void sqlInjectionStyleRegistration() throws Exception {
        String name = "Robert'); DROP TABLE users;--";
        mockMvc.perform(post("/register")
                        .param("name", name)
                        .param("email", "bobby@example.com")
                        .param("password", PASSWORD)
                        .param("confirmPassword", PASSWORD)
                        .with(csrf()))
                .andExpect(redirectedUrl("/login?registered"));

        assertThat(userRepository.findByEmail("bobby@example.com").orElseThrow().getName()).isEqualTo(name);
        assertThat(userRepository.count()).isEqualTo(1);
    }

    @Test
    @DisplayName("SQL-like text in the admin IP search is rejected")
    void sqlInjectionStyleAdminSearch() throws Exception {
        login("someone@example.com", "wrong", IP);

        mockMvc.perform(get("/admin/attempts").param("ip", "' OR 1=1 --").with(user("admin@example.com").roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(model().attribute("ipFilterInvalid", true))
                .andExpect(model().attribute("attempts", hasSize(1)));
        // With spaces: rejected as invalid and ignored
        mockMvc.perform(get("/admin/attempts").param("email", "x' OR '1'='1").with(user("admin@example.com").roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(model().attribute("emailFilterInvalid", true))
                .andExpect(model().attribute("attempts", hasSize(1)));
        // Without spaces: searched for literally, matches nothing
        mockMvc.perform(get("/admin/attempts").param("email", "x'or'1'='1").with(user("admin@example.com").roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(model().attribute("attempts", hasSize(0)));

        assertThat(loginAttemptRepository.count()).isEqualTo(1);
    }
}

package com.example.loginmonitoring.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.example.loginmonitoring.entity.Role;
import com.example.loginmonitoring.entity.User;
import com.example.loginmonitoring.support.IntegrationTestBase;

class RegistrationTest extends IntegrationTestBase {

    @Test
    @DisplayName("Test 1: registration stores the user with a BCrypt hash and the USER role")
    void successfulRegistration() throws Exception {
        mockMvc.perform(post("/register")
                        .param("name", "Asha Verma")
                        .param("email", "Asha@Example.com")
                        .param("password", PASSWORD)
                        .param("confirmPassword", PASSWORD)
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?registered"));

        User saved = userRepository.findByEmail("asha@example.com").orElseThrow();
        assertThat(saved.getName()).isEqualTo("Asha Verma");
        assertThat(saved.getRole()).isEqualTo(Role.USER);
        assertThat(saved.isEnabled()).isTrue();
        assertThat(saved.getCreatedAt()).isNotNull();
        assertThat(saved.getPasswordHash())
                .isNotEqualTo(PASSWORD)
                .startsWith("$2")       // BCrypt hash prefix ($2a$ / $2b$ / $2y$)
                .hasSize(60);
        assertThat(passwordEncoder.matches(PASSWORD, saved.getPasswordHash())).isTrue();
    }

    @Test
    @DisplayName("A 'role=ADMIN' field sent by the browser is ignored")
    void cannotChooseOwnRole() throws Exception {
        mockMvc.perform(post("/register")
                        .param("name", "Sneaky")
                        .param("email", "sneaky@example.com")
                        .param("password", PASSWORD)
                        .param("confirmPassword", PASSWORD)
                        .param("role", "ADMIN")
                        .with(csrf()))
                .andExpect(redirectedUrl("/login?registered"));

        assertThat(userRepository.findByEmail("sneaky@example.com").orElseThrow().getRole()).isEqualTo(Role.USER);
    }

    @Test
    @DisplayName("Duplicate email is rejected (case-insensitive)")
    void duplicateEmailRejected() throws Exception {
        createUser("First", "taken@example.com", PASSWORD, Role.USER);

        mockMvc.perform(post("/register")
                        .param("name", "Second")
                        .param("email", "TAKEN@example.com")
                        .param("password", PASSWORD)
                        .param("confirmPassword", PASSWORD)
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(view().name("register"))
                .andExpect(model().attributeHasFieldErrorCode("form", "email", "duplicate"));

        assertThat(userRepository.count()).isEqualTo(1);
    }

    @Test
    @DisplayName("Weak password, mismatched confirmation and bad email are rejected")
    void validationErrors() throws Exception {
        mockMvc.perform(post("/register")
                        .param("name", "")
                        .param("email", "not-an-email")
                        .param("password", "short")
                        .param("confirmPassword", "different")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(view().name("register"))
                .andExpect(model().attributeHasFieldErrors("form", "name", "email", "password", "confirmPassword"));

        mockMvc.perform(post("/register")
                        .param("name", "Letters Only")
                        .param("email", "letters@example.com")
                        .param("password", "onlyletters")
                        .param("confirmPassword", "onlyletters")
                        .with(csrf()))
                .andExpect(model().attributeHasFieldErrorCode("form", "password", "Pattern"));

        assertThat(userRepository.count()).isZero();
    }

    @Test
    @DisplayName("Passwords longer than BCrypt's 72-byte limit are rejected with a message, not an error")
    void multiBytePasswordTooLong() throws Exception {
        String password = "a1" + "\u0905".repeat(30); // 32 characters, but 92 bytes in UTF-8
        mockMvc.perform(post("/register")
                        .param("name", "Long Password")
                        .param("email", "long@example.com")
                        .param("password", password)
                        .param("confirmPassword", password)
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(model().attributeHasFieldErrorCode("form", "password", "tooLong"));

        assertThat(userRepository.count()).isZero();
    }
}

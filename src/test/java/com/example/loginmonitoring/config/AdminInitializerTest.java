package com.example.loginmonitoring.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import com.example.loginmonitoring.entity.Role;
import com.example.loginmonitoring.entity.User;
import com.example.loginmonitoring.support.IntegrationTestBase;

@TestPropertySource(properties = {
        "app.admin.email=Boss@LAMS.test",
        "app.admin.password=AdminPass42"
})
class AdminInitializerTest extends IntegrationTestBase {

    @Autowired
    private AdminInitializer adminInitializer;

    @Test
    @DisplayName("Admin account is created from configuration and re-running is safe")
    void createsAdminOnceAndIsIdempotent() throws Exception {
        adminInitializer.run(null);
        adminInitializer.run(null);

        assertThat(userRepository.count()).isEqualTo(1);
        User admin = userRepository.findByEmail("boss@lams.test").orElseThrow();
        assertThat(admin.getRole()).isEqualTo(Role.ADMIN);
        assertThat(admin.getPasswordHash()).startsWith("$2").isNotEqualTo("AdminPass42");

        login("boss@lams.test", "AdminPass42", "10.0.0.1").andExpect(redirectedUrl("/admin"));
    }

    @Test
    @DisplayName("A user registered with the admin email is repaired to the configured admin")
    void repairsExistingAccount() throws Exception {
        createUser("Impostor", "boss@lams.test", "Impostor99", Role.USER);

        adminInitializer.run(null);

        User admin = userRepository.findByEmail("boss@lams.test").orElseThrow();
        assertThat(admin.getRole()).isEqualTo(Role.ADMIN);
        assertThat(passwordEncoder.matches("AdminPass42", admin.getPasswordHash())).isTrue();
        assertThat(passwordEncoder.matches("Impostor99", admin.getPasswordHash())).isFalse();
    }

    @Test
    @DisplayName("Nobody can register the reserved admin email")
    void cannotRegisterAdminEmail() throws Exception {
        mockMvc.perform(post("/register")
                        .param("name", "Impostor")
                        .param("email", "boss@lams.test")
                        .param("password", "Impostor99")
                        .param("confirmPassword", "Impostor99")
                        .with(csrf()))
                .andExpect(model().attributeHasFieldErrorCode("form", "email", "duplicate"));

        assertThat(userRepository.count()).isZero();
    }
}

package com.example.loginmonitoring.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import com.example.loginmonitoring.entity.AlertType;
import com.example.loginmonitoring.entity.LockType;
import com.example.loginmonitoring.entity.LoginAttempt;
import com.example.loginmonitoring.entity.LoginOutcome;
import com.example.loginmonitoring.entity.RiskFlag;
import com.example.loginmonitoring.entity.Role;
import com.example.loginmonitoring.entity.SecurityAlert;
import com.example.loginmonitoring.service.SimulatorService.Scenario;
import com.example.loginmonitoring.support.IntegrationTestBase;

class SimulatorServiceTest extends IntegrationTestBase {

    private static final String TARGET = "victim@example.com";

    @Autowired
    private SimulatorService simulator;

    @BeforeEach
    void createTarget() {
        createUser("Victim", TARGET, PASSWORD, Role.USER);
    }

    @Test
    @DisplayName("Brute force: account locked for the attacker IP after 5 failures")
    void bruteForce() {
        SimulatorService.Result result = simulator.run(Scenario.BRUTE_FORCE, TARGET);
        assertThat(result.steps()).hasSize(7);
        assertThat(result.steps().get(4)).contains("RULE 1");
        assertThat(accountLockRepository.findAll()).singleElement()
                .satisfies(l -> assertThat(l.getType()).isEqualTo(LockType.ACCOUNT_IP));
        assertThat(loginAttemptRepository.countByOutcome(LoginOutcome.BLOCKED)).isEqualTo(2);
        assertThat(loginAttemptRepository.findAll()).allSatisfy(a -> {
            assertThat(a.isSimulated()).isTrue();
            assertThat(a.getBrowser()).isEqualTo("Hydra (attack tool)");
        });
    }

    @Test
    @DisplayName("Credential stuffing: the IP is blocked after 4 different accounts")
    void credentialStuffing() {
        simulator.run(Scenario.CREDENTIAL_STUFFING, TARGET);
        assertThat(blockedIpRepository.findAll()).singleElement().satisfies(b -> {
            assertThat(b.getIpAddress()).isEqualTo("198.51.100.23");
            assertThat(b.isSimulated()).isTrue();
        });
        assertThat(alertRepository.findAll()).extracting(SecurityAlert::getType).contains(AlertType.CREDENTIAL_STUFFING);
    }

    @Test
    @DisplayName("Distributed attack: the account is locked for new IPs, the owner's known IP still works")
    void distributed() throws Exception {
        login(TARGET, PASSWORD, "10.0.0.1").andExpect(redirectedUrl("/dashboard"));
        simulator.run(Scenario.DISTRIBUTED, TARGET);

        assertThat(accountLockRepository.findAll()).anySatisfy(l -> assertThat(l.getType()).isEqualTo(LockType.ACCOUNT));
        login(TARGET, PASSWORD, "10.0.0.99").andExpect(redirectedUrl("/login?locked"));
        login(TARGET, PASSWORD, "10.0.0.1").andExpect(redirectedUrl("/dashboard"));
    }

    @Test
    @DisplayName("Account takeover: the successful login is flagged with VPN + after failures and raises a critical alert")
    void accountTakeover() {
        simulator.run(Scenario.ACCOUNT_TAKEOVER, TARGET);
        LoginAttempt success = loginAttemptRepository.findAll().stream()
                .filter(a -> a.getOutcome() == LoginOutcome.SUCCESS).findFirst().orElseThrow();
        assertThat(success.getRiskFlagList()).contains(RiskFlag.AFTER_FAILURES, RiskFlag.VPN_OR_HOSTING);
        assertThat(alertRepository.findAll()).anySatisfy(a -> assertThat(a.getType()).isEqualTo(AlertType.SUSPICIOUS_LOGIN));
        assertThat(ipInfoRepository.findById("192.0.2.150").orElseThrow().getCountry()).isEqualTo("Singapore");
    }

    @Test
    @DisplayName("Account takeover needs an existing account")
    void takeoverNeedsAccount() {
        assertThatThrownBy(() -> simulator.run(Scenario.ACCOUNT_TAKEOVER, "nobody@example.com"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Clear removes every simulated row and keeps real data")
    void clearKeepsRealData() throws Exception {
        login(TARGET, "Wrong1111", "10.0.0.1");
        for (Scenario scenario : Scenario.values()) {
            simulator.run(scenario, TARGET);
        }
        assertThat(loginAttemptRepository.count()).isGreaterThan(20);

        simulator.clear();
        assertThat(loginAttemptRepository.findAll()).singleElement()
                .satisfies(a -> assertThat(a.getIpAddress()).isEqualTo("10.0.0.1"));
        assertThat(blockedIpRepository.count()).isZero();
        assertThat(accountLockRepository.count()).isZero();
        assertThat(alertRepository.count()).isZero();
        assertThat(ipInfoRepository.count()).isZero();
    }

    @Test
    @DisplayName("The simulator page runs scenarios via POST and writes the audit log")
    void viaController() throws Exception {
        mockMvc.perform(post("/admin/simulator/run").param("scenario", "BRUTE_FORCE").param("target", TARGET)
                        .with(admin()).with(csrf()))
                .andExpect(redirectedUrl("/admin/simulator"))
                .andExpect(flash().attributeExists("result"));
        mockMvc.perform(post("/admin/simulator/run").param("scenario", "NOPE").param("target", TARGET)
                        .with(admin()).with(csrf()))
                .andExpect(flash().attribute("error", "Unknown scenario."));
        assertThat(adminActionRepository.findAll()).hasSize(1);
    }
}

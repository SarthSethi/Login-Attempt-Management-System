package com.example.loginmonitoring.support;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import java.time.LocalDateTime;

import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import com.example.loginmonitoring.entity.Role;
import com.example.loginmonitoring.entity.User;
import com.example.loginmonitoring.repository.AccountLockRepository;
import com.example.loginmonitoring.repository.AdminActionRepository;
import com.example.loginmonitoring.repository.BlockedIpRepository;
import com.example.loginmonitoring.repository.IpAllowlistRepository;
import com.example.loginmonitoring.repository.IpInfoRepository;
import com.example.loginmonitoring.repository.LoginAttemptRepository;
import com.example.loginmonitoring.repository.SecurityAlertRepository;
import com.example.loginmonitoring.repository.UserRepository;
import com.example.loginmonitoring.service.AllowlistService;

/**
 * Common setup for the integration tests: full Spring context, MockMvc,
 * a controllable clock and an empty database before every test.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(IntegrationTestBase.TestClockConfig.class)
public abstract class IntegrationTestBase {

    protected static final String PASSWORD = "Secret123";

    @TestConfiguration
    public static class TestClockConfig {
        @Bean
        @Primary
        public MutableClock testClock() {
            return new MutableClock();
        }
    }

    @Autowired
    protected MockMvc mockMvc;

    @Autowired
    protected MutableClock clock;

    @Autowired
    protected UserRepository userRepository;

    @Autowired
    protected LoginAttemptRepository loginAttemptRepository;

    @Autowired
    protected BlockedIpRepository blockedIpRepository;

    @Autowired
    protected AccountLockRepository accountLockRepository;

    @Autowired
    protected SecurityAlertRepository alertRepository;

    @Autowired
    protected IpInfoRepository ipInfoRepository;

    @Autowired
    protected IpAllowlistRepository allowlistRepository;

    @Autowired
    protected AdminActionRepository adminActionRepository;

    @Autowired
    protected AllowlistService allowlistService;

    @Autowired
    protected SessionRegistry sessionRegistry;

    @Autowired
    protected PasswordEncoder passwordEncoder;

    @BeforeEach
    void cleanDatabaseAndResetClock() {
        loginAttemptRepository.deleteAll();
        blockedIpRepository.deleteAll();
        accountLockRepository.deleteAll();
        alertRepository.deleteAll();
        ipInfoRepository.deleteAll();
        allowlistRepository.findAll().forEach(e -> allowlistService.remove(e.getId()));
        adminActionRepository.deleteAll();
        userRepository.deleteAll();
        // Sessions of earlier tests must not show up as "active sessions" in this one
        for (Object principal : sessionRegistry.getAllPrincipals()) {
            sessionRegistry.getAllSessions(principal, true)
                    .forEach(info -> sessionRegistry.removeSessionInformation(info.getSessionId()));
        }
        clock.reset();
    }

    /** A signed-in administrator for MockMvc requests. */
    protected static RequestPostProcessor admin() {
        return SecurityMockMvcRequestPostProcessors.user("admin@example.com").roles("ADMIN");
    }

    /** Submits the login form with a given browser User-Agent. */
    protected ResultActions login(String email, String password, String ip, String userAgent) throws Exception {
        return mockMvc.perform(post("/login")
                .param("email", email)
                .param("password", password)
                .header("User-Agent", userAgent)
                .with(csrf())
                .with(fromIp(ip)));
    }

    protected static final String CHROME_WINDOWS =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36";
    protected static final String FIREFOX_LINUX =
            "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0";

    /** Makes a MockMvc request look like it came from the given client IP (TCP address). */
    protected static RequestPostProcessor fromIp(String ip) {
        return request -> {
            request.setRemoteAddr(ip);
            return request;
        };
    }

    /** Submits the login form exactly like a browser would (CSRF token, Chrome User-Agent). */
    protected ResultActions login(String email, String password, String ip) throws Exception {
        return login(email, password, ip, CHROME_WINDOWS);
    }

    protected User createUser(String name, String email, String rawPassword, Role role) {
        return userRepository.save(new User(name, email, passwordEncoder.encode(rawPassword), role,
                LocalDateTime.now(clock)));
    }
}

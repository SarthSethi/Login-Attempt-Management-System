package com.example.loginmonitoring.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.loginmonitoring.security.ClientIpResolver;
import com.example.loginmonitoring.security.CsrfFailureHandler;
import com.example.loginmonitoring.security.LoginFailureHandler;
import com.example.loginmonitoring.security.LoginFormFields;
import com.example.loginmonitoring.security.LoginProtectionFilter;
import com.example.loginmonitoring.security.LoginSuccessHandler;
import com.example.loginmonitoring.service.CustomUserDetailsService;
import com.example.loginmonitoring.service.LoginProtectionService;

import jakarta.servlet.DispatcherType;

/**
 * Spring Security setup.
 *
 * <p>Order of the filters that matter for "POST /login":
 * <pre>
 *   CsrfFilter  -&gt;  LoginProtectionFilter          -&gt;  UsernamePasswordAuthenticationFilter
 *   (valid token?)    (IP blocked? account locked?)       (email + password correct?)
 *                                              |- yes: LoginSuccessHandler
 *                                              '- no : LoginFailureHandler
 * </pre>
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Checks email + password against the users table.
     * "Account disabled" is only reported AFTER the password was found correct; with a wrong
     * password the user sees the normal "Invalid email or password" message, so the message
     * never reveals which emails have an account.
     */
    @Bean
    public DaoAuthenticationProvider authenticationProvider(CustomUserDetailsService userDetailsService,
                                                            PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        provider.setPreAuthenticationChecks(user -> { });
        provider.setPostAuthenticationChecks(user -> {
            if (!user.isEnabled()) {
                throw new DisabledException("Account disabled");
            }
        });
        return provider;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   ClientIpResolver clientIpResolver,
                                                   LoginProtectionService protectionService,
                                                   LoginSuccessHandler successHandler,
                                                   LoginFailureHandler failureHandler,
                                                   SessionRegistry sessionRegistry) throws Exception {

        LoginProtectionFilter protectionFilter = new LoginProtectionFilter(clientIpResolver, protectionService);

        http
            .authorizeHttpRequests(auth -> auth
                .dispatcherTypeMatchers(DispatcherType.ERROR, DispatcherType.FORWARD).permitAll()
                .requestMatchers("/login", "/register", "/error", "/css/**", "/js/**", "/img/**", "/favicon.svg", "/favicon.ico").permitAll()
                .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                .requestMatchers("/admin", "/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated())

            // Block / lock check happens before the email/password check
            .addFilterBefore(protectionFilter, UsernamePasswordAuthenticationFilter.class)

            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .usernameParameter(LoginFormFields.EMAIL)
                .passwordParameter(LoginFormFields.PASSWORD)
                .successHandler(successHandler)
                .failureHandler(failureHandler)
                .permitAll())

            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID"))

            // New session id after login (prevents session fixation).
            // Every session is registered so users can sign out their other devices.
            .sessionManagement(session -> session
                .sessionFixation(fixation -> fixation.changeSessionId())
                .sessionConcurrency(concurrency -> concurrency
                    .maximumSessions(-1)
                    .sessionRegistry(sessionRegistry)
                    .expiredUrl("/login?expired")))

            // CSRF protection is on by default; tokens are added to every Thymeleaf form.
            // A form with an old token (session gone, or signed in/out in another tab) is still refused,
            // but the user gets a clear message instead of a bare 403 page.
            .exceptionHandling(exceptions -> exceptions.accessDeniedHandler(new CsrfFailureHandler()))

            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp.policyDirectives(
                    "default-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")));

        return http.build();
    }
}

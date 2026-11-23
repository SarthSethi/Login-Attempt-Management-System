package com.example.loginmonitoring.config;

import java.time.Clock;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.session.HttpSessionEventPublisher;

@Configuration
public class AppConfig {

    /**
     * All services read the current time from this clock (always UTC).
     * Tests replace it with a clock they can move forward, so "wait 15 minutes"
     * can be tested instantly.
     */
    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    /** Keeps track of every logged-in session (used for "sign out other devices"). */
    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    /** Tells the session registry when a session ends. */
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }
}

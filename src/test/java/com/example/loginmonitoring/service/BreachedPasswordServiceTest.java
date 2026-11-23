package com.example.loginmonitoring.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.example.loginmonitoring.config.IntegrationProperties;
import com.example.loginmonitoring.service.intel.BreachedPasswordService;

class BreachedPasswordServiceTest {

    @Test
    @DisplayName("Only the first 5 characters of the SHA-1 hash would be sent; the rest is compared locally")
    void kAnonymityParsing() throws Exception {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        var sha1 = BreachedPasswordService.class.getDeclaredMethod("sha1Hex", String.class);
        sha1.setAccessible(true);
        assertThat(sha1.invoke(null, "password")).isEqualTo("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");

        var find = BreachedPasswordService.class.getDeclaredMethod("findCount", String.class, String.class);
        find.setAccessible(true);
        String body = "0018A45C4D1DEF81644B54AB7F969B88D65:10\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\n"
                + "011053FD0102E94D6AE2F8B83D76FAF94F6:0\r\n";
        assertThat(find.invoke(null, body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8")).isEqualTo(9545824L);
        assertThat(find.invoke(null, body, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")).isEqualTo(0L);
    }

    @Test
    @DisplayName("Switched off, or the service is unreachable: the check is skipped, never blocks")
    void failsOpen() {
        IntegrationProperties off = new IntegrationProperties(false, "http://x/{ip}", 40, false,
                "https://x/{prefix}", Duration.ofMillis(200), Duration.ofDays(90));
        assertThat(new BreachedPasswordService(off).breachCount("password")).isEmpty();

        IntegrationProperties unreachable = new IntegrationProperties(false, "http://x/{ip}", 40, true,
                "http://127.0.0.1:9/range/{prefix}", Duration.ofMillis(300), Duration.ofDays(90));
        assertThat(new BreachedPasswordService(unreachable).breachCount("password")).isEmpty();
    }
}

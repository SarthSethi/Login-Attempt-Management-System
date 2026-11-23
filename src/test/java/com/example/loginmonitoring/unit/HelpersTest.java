package com.example.loginmonitoring.unit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.example.loginmonitoring.config.LoginSecurityProperties;
import com.example.loginmonitoring.entity.IpInfo;
import com.example.loginmonitoring.entity.IpInfoStatus;
import com.example.loginmonitoring.service.AllowlistService;
import com.example.loginmonitoring.service.intel.DeviceInfo;
import com.example.loginmonitoring.service.intel.IpClassifier;
import com.example.loginmonitoring.service.intel.UserAgentParser;

/** Plain unit tests (no Spring context) for the small helper classes. */
class HelpersTest {

    @Test
    @DisplayName("User-Agent parser recognises common browsers, phones and attack tools")
    void userAgents() {
        assertThat(UserAgentParser.parse("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                + "(KHTML, like Gecko) Chrome/131.0 Safari/537.36 Edg/131.0"))
                .isEqualTo(new DeviceInfo("Edge", "Windows 10/11", DeviceInfo.DESKTOP));
        assertThat(UserAgentParser.parse("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 "
                + "(KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"))
                .isEqualTo(new DeviceInfo("Safari", "iOS", DeviceInfo.MOBILE));
        assertThat(UserAgentParser.parse("Mozilla/5.0 (Linux; Android 14; SM-A546E) AppleWebKit/537.36 "
                + "(KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36"))
                .isEqualTo(new DeviceInfo("Chrome", "Android", DeviceInfo.MOBILE));
        assertThat(UserAgentParser.parse("Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 "
                + "(KHTML, like Gecko) Version/17.5 Safari/604.1").deviceType()).isEqualTo(DeviceInfo.TABLET);
        assertThat(UserAgentParser.parse("python-requests/2.32.3").automated()).isTrue();
        assertThat(UserAgentParser.parse("curl/8.5.0").browser()).isEqualTo("curl");
        assertThat(UserAgentParser.parse("Mozilla/4.0 (Hydra)").browser()).isEqualTo("Hydra (attack tool)");
        assertThat(UserAgentParser.parse(null).automated()).isTrue();
        assertThat(UserAgentParser.parse("  ").automated()).isTrue();
    }

    @Test
    @DisplayName("Private and reserved IPs are recognised without any network call")
    void ipClassifier() {
        assertThat(IpClassifier.classify("10.1.2.3")).isEqualTo(IpInfoStatus.PRIVATE);
        assertThat(IpClassifier.classify("192.168.0.1")).isEqualTo(IpInfoStatus.PRIVATE);
        assertThat(IpClassifier.classify("0:0:0:0:0:0:0:1")).isEqualTo(IpInfoStatus.PRIVATE);
        assertThat(IpClassifier.classify("203.0.113.5")).isEqualTo(IpInfoStatus.RESERVED);
        assertThat(IpClassifier.classify("unknown")).isEqualTo(IpInfoStatus.RESERVED);
        assertThat(IpClassifier.classify("8.8.8.8")).isNull();
        assertThat(IpClassifier.isPublic("81.97.145.24")).isTrue();
    }

    @Test
    @DisplayName("Country code becomes a flag; labels for private and unknown addresses")
    void ipInfoLabels() {
        IpInfo india = new IpInfo("49.36.1.1", IpInfoStatus.OK, null).withLocation("India", "in", "Maharashtra", "Mumbai");
        assertThat(india.getFlag()).isEqualTo("🇮🇳");
        assertThat(india.getLocationLabel()).isEqualTo("Mumbai, India");
        assertThat(new IpInfo("10.0.0.1", IpInfoStatus.PRIVATE, null).getLocationLabel()).isEqualTo("Private network");
        assertThat(new IpInfo("8.8.8.8", IpInfoStatus.FAILED, null).getLocationLabel()).isEqualTo("Unknown");
    }

    @Test
    @DisplayName("Allow-list entries are validated without DNS lookups")
    void cidrValidation() {
        assertThat(AllowlistService.normalizeCidr(" 192.168.1.0/24 ")).isEqualTo("192.168.1.0/24");
        assertThat(AllowlistService.normalizeCidr("203.0.113.7")).isEqualTo("203.0.113.7");
        assertThat(AllowlistService.normalizeCidr("2001:db8::/32")).isEqualTo("2001:db8:0:0:0:0:0:0/32");
        assertThatThrownBy(() -> AllowlistService.normalizeCidr("example.com")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> AllowlistService.normalizeCidr("10.0.0.0/33")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> AllowlistService.normalizeCidr("")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Repeat blocks get longer: 15 min, 1 h, 24 h, 24 h ...")
    void escalation() {
        LoginSecurityProperties p = new LoginSecurityProperties(5, Duration.ofMinutes(10), Duration.ofMinutes(15),
                4, 10, 8, 3, List.of(Duration.ofHours(1), Duration.ofHours(24)), Duration.ofHours(24),
                Duration.ofDays(90));
        assertThat(p.blockDurationForLevel(1)).isEqualTo(Duration.ofMinutes(15));
        assertThat(p.blockDurationForLevel(2)).isEqualTo(Duration.ofHours(1));
        assertThat(p.blockDurationForLevel(3)).isEqualTo(Duration.ofHours(24));
        assertThat(p.blockDurationForLevel(9)).isEqualTo(Duration.ofHours(24));
    }
}

package com.example.loginmonitoring.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import com.example.loginmonitoring.config.ClientIpProperties;

/** Plain unit tests (no Spring context) for client IP detection. */
class ClientIpResolverTest {

    private static ClientIpResolver resolverTrusting(String... proxies) {
        return new ClientIpResolver(new ClientIpProperties(List.of(proxies), List.of(), false));
    }

    private static ClientIpResolver onRender() {
        return new ClientIpResolver(new ClientIpProperties(List.of(), List.of(), true));
    }

    private static MockHttpServletRequest request(String remoteAddr, String forwardedFor) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        request.setRemoteAddr(remoteAddr);
        if (forwardedFor != null) {
            request.addHeader("X-Forwarded-For", forwardedFor);
        }
        return request;
    }

    @Test
    @DisplayName("Without trusted proxies the direct address is used and X-Forwarded-For is ignored")
    void ignoresHeaderWithoutTrustedProxy() {
        ClientIpResolver resolver = resolverTrusting();
        assertThat(resolver.resolve(request("203.0.113.5", null))).isEqualTo("203.0.113.5");
        // A client trying to fake its IP to dodge the block
        assertThat(resolver.resolve(request("203.0.113.5", "1.2.3.4"))).isEqualTo("203.0.113.5");
    }

    @Test
    @DisplayName("Header is ignored when the request did not come from a trusted proxy")
    void ignoresHeaderFromUntrustedSender() {
        ClientIpResolver resolver = resolverTrusting("10.0.0.0/8");
        assertThat(resolver.resolve(request("203.0.113.5", "1.2.3.4"))).isEqualTo("203.0.113.5");
    }

    @Test
    @DisplayName("Behind a trusted proxy the client address from X-Forwarded-For is used")
    void usesHeaderFromTrustedProxy() {
        ClientIpResolver resolver = resolverTrusting("10.0.0.0/8");
        assertThat(resolver.resolve(request("10.1.2.3", "198.51.100.7"))).isEqualTo("198.51.100.7");
    }

    @Test
    @DisplayName("Spoofed entries added by the client (left side of the header) are skipped")
    void rightmostUntrustedAddressWins() {
        ClientIpResolver resolver = resolverTrusting("10.0.0.0/8");
        // client sent "X-Forwarded-For: 6.6.6.6"; the proxy appended the real address
        assertThat(resolver.resolve(request("10.1.2.3", "6.6.6.6, 198.51.100.7"))).isEqualTo("198.51.100.7");
        // two proxy hops, both trusted
        assertThat(resolver.resolve(request("10.1.2.3", "6.6.6.6, 198.51.100.7, 10.9.9.9")))
                .isEqualTo("198.51.100.7");
    }

    @Test
    @DisplayName("Render-style chain (client, Cloudflare, internal proxy) resolves to the real client")
    void renderAndCloudflareChain() {
        ClientIpResolver resolver = resolverTrusting("10.0.0.0/8", "162.158.0.0/15");
        assertThat(resolver.resolve(request("10.226.0.5", "81.97.145.24, 162.158.79.68, 10.226.0.196")))
                .isEqualTo("81.97.145.24");
        // Client tries to hide behind a fake first entry
        assertThat(resolver.resolve(request("10.226.0.5", "1.2.3.4, 81.97.145.24, 162.158.79.68, 10.226.0.196")))
                .isEqualTo("81.97.145.24");
    }

    @Test
    @DisplayName("Garbage in the header falls back to the last trusted address")
    void invalidHeaderValues() {
        ClientIpResolver resolver = resolverTrusting("10.0.0.0/8");
        assertThat(resolver.resolve(request("10.1.2.3", "not-an-ip"))).isEqualTo("10.1.2.3");
        assertThat(resolver.resolve(request("10.1.2.3", "evil.example.com"))).isEqualTo("10.1.2.3");
        assertThat(resolver.resolve(request("10.1.2.3", "   "))).isEqualTo("10.1.2.3");
    }

    @Test
    @DisplayName("IPv6 addresses are supported and normalised")
    void ipv6() {
        ClientIpResolver resolver = resolverTrusting("::1");
        assertThat(resolver.resolve(request("::1", null))).isEqualTo("0:0:0:0:0:0:0:1");
        assertThat(resolver.resolve(request("0:0:0:0:0:0:0:1", "2001:db8::42"))).isEqualTo("2001:db8:0:0:0:0:0:42");
        assertThat(resolverTrusting().resolve(request("2001:DB8::42", null))).isEqualTo("2001:db8:0:0:0:0:0:42");
    }

    @Test
    @DisplayName("normalize() accepts only IP literals (no DNS lookups for host names)")
    void normalize() {
        assertThat(ClientIpResolver.normalize("192.168.1.10")).isEqualTo("192.168.1.10");
        assertThat(ClientIpResolver.normalize(" 192.168.1.10 ")).isEqualTo("192.168.1.10");
        assertThat(ClientIpResolver.normalize("[2001:db8::1]")).isEqualTo("2001:db8:0:0:0:0:0:1");
        assertThat(ClientIpResolver.normalize("fe80::1%en0")).isEqualTo("fe80:0:0:0:0:0:0:1");
        assertThat(ClientIpResolver.normalize("localhost")).isNull();
        assertThat(ClientIpResolver.normalize("example.com")).isNull();
        assertThat(ClientIpResolver.normalize("999.1.1.1")).isNull();
        assertThat(ClientIpResolver.normalize("")).isNull();
        assertThat(ClientIpResolver.normalize(null)).isNull();
    }

    @Test
    @DisplayName("On Render the visitor IP comes from Cloudflare's CF-Connecting-IP header")
    void renderUsesCloudflareHeader() {
        MockHttpServletRequest request = request("10.226.0.5", "6.6.6.6, 81.97.145.24, 162.158.79.68");
        request.addHeader("CF-Connecting-IP", "81.97.145.24");
        ClientIpResolver.Resolution resolution = onRender().resolveDetailed(request);
        assertThat(resolution.ip()).isEqualTo("81.97.145.24");
        assertThat(resolution.method()).isEqualTo("Header CF-Connecting-IP");
        assertThat(resolution.headers()).containsKey("CF-Connecting-IP").containsKey("X-Forwarded-For");
    }

    @Test
    @DisplayName("On Render, True-Client-IP is used only when CF-Connecting-IP is missing; garbage is ignored")
    void renderFallbacks() {
        MockHttpServletRequest request = request("10.226.0.5", null);
        request.addHeader("CF-Connecting-IP", "not-an-ip");
        request.addHeader("True-Client-IP", "2001:db8::7");
        assertThat(onRender().resolve(request)).isEqualTo("2001:db8:0:0:0:0:0:7");

        // No usable header at all: the connection address is used
        assertThat(onRender().resolve(request("10.226.0.5", null))).isEqualTo("10.226.0.5");
    }

    @Test
    @DisplayName("Off Render, a configured header is trusted only from a trusted proxy")
    void configuredHeaderNeedsTrustedProxy() {
        ClientIpResolver resolver = new ClientIpResolver(
                new ClientIpProperties(List.of("10.0.0.0/8"), List.of("CF-Connecting-IP"), false));
        MockHttpServletRequest fromProxy = request("10.1.2.3", null);
        fromProxy.addHeader("CF-Connecting-IP", "198.51.100.7");
        assertThat(resolver.resolve(fromProxy)).isEqualTo("198.51.100.7");

        MockHttpServletRequest direct = request("203.0.113.5", null);
        direct.addHeader("CF-Connecting-IP", "1.2.3.4"); // a visitor trying to fake its IP
        assertThat(resolver.resolve(direct)).isEqualTo("203.0.113.5");
    }
}

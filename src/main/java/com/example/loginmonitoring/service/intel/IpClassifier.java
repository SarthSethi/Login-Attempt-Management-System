package com.example.loginmonitoring.service.intel;

import java.util.List;

import org.springframework.security.web.util.matcher.IpAddressMatcher;

import com.example.loginmonitoring.entity.IpInfoStatus;
import com.example.loginmonitoring.security.ClientIpResolver;

/** Recognises private and reserved addresses locally, without asking an outside service. */
public final class IpClassifier {

    private static final List<IpAddressMatcher> PRIVATE = matchers(
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
            "100.64.0.0/10", "0.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10");

    /** Documentation / test ranges (RFC 5737, RFC 3849) - the attack simulator uses these. */
    private static final List<IpAddressMatcher> RESERVED = matchers(
            "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
            "224.0.0.0/4", "240.0.0.0/4");

    private IpClassifier() {
    }

    /** PRIVATE, RESERVED, or null for a normal public address (or text that is not an IP). */
    public static IpInfoStatus classify(String ip) {
        String normalized = ClientIpResolver.normalize(ip);
        if (normalized == null) {
            return IpInfoStatus.RESERVED;
        }
        for (IpAddressMatcher matcher : PRIVATE) {
            if (matcher.matches(normalized)) {
                return IpInfoStatus.PRIVATE;
            }
        }
        for (IpAddressMatcher matcher : RESERVED) {
            if (matcher.matches(normalized)) {
                return IpInfoStatus.RESERVED;
            }
        }
        return null;
    }

    public static boolean isPublic(String ip) {
        return classify(ip) == null;
    }

    private static List<IpAddressMatcher> matchers(String... ranges) {
        return List.of(ranges).stream().map(IpAddressMatcher::new).toList();
    }
}

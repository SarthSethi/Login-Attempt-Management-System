package com.example.loginmonitoring.security;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.stereotype.Component;

import com.example.loginmonitoring.config.ClientIpProperties;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Works out the IP address of the visitor that sent a request.
 *
 * <p>Order of the checks:
 * <ol>
 *   <li>If the request came from a trusted proxy (or the app runs on Render, where every request
 *       passes through Render's proxy and Cloudflare), use the visitor IP from a trusted header
 *       such as {@code CF-Connecting-IP}. Cloudflare always overwrites that header, so a visitor
 *       cannot fake it.</li>
 *   <li>Otherwise, if the request came from a trusted proxy, read X-Forwarded-For from right to
 *       left, skipping our own proxies, and use the first address that is not a trusted proxy.
 *       Entries further left were typed by the client and are not trusted.</li>
 *   <li>Otherwise use the address of the TCP connection, which a client cannot fake.</li>
 * </ol>
 * The result is normalised (for example IPv6 "::1" becomes "0:0:0:0:0:0:0:1") so the same
 * client is always counted under the same text.
 */
@Component
public class ClientIpResolver {

    private static final Logger log = LoggerFactory.getLogger(ClientIpResolver.class);

    static final String FORWARDED_FOR_HEADER = "X-Forwarded-For";
    static final List<String> RENDER_HEADERS = List.of("CF-Connecting-IP", "True-Client-IP");

    /** Headers shown on the admin "connection check" panel. */
    private static final List<String> DIAGNOSTIC_HEADERS =
            List.of("CF-Connecting-IP", "True-Client-IP", "X-Forwarded-For", "X-Real-IP", "CF-IPCountry");

    private static final Pattern IPV4 = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");
    private static final Pattern IPV6 = Pattern.compile("^[0-9a-fA-F:.]+$");

    /** How the address was found, for the connection-check panel. */
    public record Resolution(String ip, String method, String remoteAddress, Map<String, String> headers) {
    }

    private final List<IpAddressMatcher> trustedProxies;
    private final List<String> trustedProxyText;
    private final List<String> clientIpHeaders;
    private final boolean render;
    private final AtomicBoolean untrustedHeaderWarningLogged = new AtomicBoolean(false);

    public ClientIpResolver(ClientIpProperties properties) {
        this.trustedProxyText = properties.trustedProxies().stream()
                .map(String::trim)
                .filter(entry -> !entry.isEmpty())
                .toList();
        this.trustedProxies = trustedProxyText.stream().map(IpAddressMatcher::new).toList();
        this.render = properties.render();
        List<String> headers = properties.headers().stream().map(String::trim).filter(h -> !h.isEmpty()).toList();
        this.clientIpHeaders = headers.isEmpty() && render ? RENDER_HEADERS : headers;

        if (render) {
            log.info("Client IP: running on Render - visitor IP is read from {}", clientIpHeaders);
        } else if (trustedProxies.isEmpty()) {
            log.info("Client IP: using the direct connection address (no trusted proxies configured)");
        } else {
            log.info("Client IP: proxy headers are trusted only from {} configured proxy range(s)", trustedProxies.size());
        }
    }

    public String resolve(HttpServletRequest request) {
        return resolveDetailed(request).ip();
    }

    public Resolution resolveDetailed(HttpServletRequest request) {
        Map<String, String> seen = new LinkedHashMap<>();
        for (String name : DIAGNOSTIC_HEADERS) {
            String value = request.getHeader(name);
            if (value != null) {
                seen.put(name, value.length() > 200 ? value.substring(0, 200) + "..." : value);
            }
        }

        String remoteAddress = normalize(request.getRemoteAddr());
        if (remoteAddress == null) {
            return new Resolution("unknown", "No usable connection address", request.getRemoteAddr(), seen);
        }
        boolean fromTrustedProxy = isTrustedProxy(remoteAddress);

        // 1. A visitor-IP header set by a proxy we trust
        if (render || fromTrustedProxy) {
            for (String headerName : clientIpHeaders) {
                String candidate = normalize(firstValue(request.getHeader(headerName)));
                if (candidate != null) {
                    return new Resolution(candidate, "Header " + headerName, remoteAddress, seen);
                }
            }
        }

        String forwardedFor = request.getHeader(FORWARDED_FOR_HEADER);

        // 2. X-Forwarded-For, but only when the sender is one of our proxies
        if (fromTrustedProxy) {
            if (forwardedFor == null || forwardedFor.isBlank()) {
                return new Resolution(remoteAddress, "Trusted proxy (no X-Forwarded-For)", remoteAddress, seen);
            }
            return new Resolution(walkForwardedFor(forwardedFor, remoteAddress),
                    "X-Forwarded-For (trusted proxy)", remoteAddress, seen);
        }

        if (forwardedFor != null && untrustedHeaderWarningLogged.compareAndSet(false, true)) {
            // Normal for a client trying to spoof its IP; but if EVERY request has it, the app is
            // behind a proxy that is missing from TRUSTED_PROXIES and all users share one IP.
            log.warn("Ignoring X-Forwarded-For from untrusted address {}. If this application runs behind "
                    + "a reverse proxy, add the proxy's address range to TRUSTED_PROXIES.", remoteAddress);
        }

        // 3. The TCP connection address
        return new Resolution(remoteAddress, "Direct connection", remoteAddress, seen);
    }

    public boolean isRender() {
        return render;
    }

    private String walkForwardedFor(String header, String remoteAddress) {
        String[] hops = header.split(",");
        String clientAddress = remoteAddress;
        for (int i = hops.length - 1; i >= 0; i--) {
            String hop = normalize(hops[i]);
            if (hop == null) {
                // Garbage in the header: stop and use the last address we could trust.
                break;
            }
            clientAddress = hop;
            if (!isTrustedProxy(hop)) {
                break;
            }
        }
        return clientAddress;
    }

    private static String firstValue(String header) {
        if (header == null) {
            return null;
        }
        int comma = header.indexOf(',');
        return comma >= 0 ? header.substring(0, comma) : header;
    }

    private boolean isTrustedProxy(String address) {
        for (IpAddressMatcher matcher : trustedProxies) {
            if (matcher.matches(address)) {
                return true;
            }
        }
        return false;
    }

    /** Number of trusted proxy ranges (for the connection-check panel). */
    public int trustedProxyCount() {
        return trustedProxyText.size();
    }

    public List<String> clientIpHeaders() {
        return clientIpHeaders;
    }

    /**
     * Returns the canonical text form of an IP literal, or null if the value is not an IP
     * address. Host names are rejected before calling InetAddress so no DNS lookup happens.
     */
    public static String normalize(String value) {
        if (value == null) {
            return null;
        }
        String candidate = value.trim();
        if (candidate.startsWith("[") && candidate.endsWith("]")) {
            candidate = candidate.substring(1, candidate.length() - 1);
        }
        int zoneIndex = candidate.indexOf('%');
        if (zoneIndex >= 0) {
            candidate = candidate.substring(0, zoneIndex);
        }
        if (candidate.isEmpty() || candidate.length() > 45) {
            return null;
        }
        boolean looksLikeIpv4 = IPV4.matcher(candidate).matches();
        boolean looksLikeIpv6 = candidate.indexOf(':') >= 0 && IPV6.matcher(candidate).matches();
        if (!looksLikeIpv4 && !looksLikeIpv6) {
            return null;
        }
        try {
            return InetAddress.getByName(candidate).getHostAddress();
        } catch (UnknownHostException ex) {
            return null;
        }
    }
}

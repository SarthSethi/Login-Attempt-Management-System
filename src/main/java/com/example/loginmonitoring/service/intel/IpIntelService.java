package com.example.loginmonitoring.service.intel;

import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Limit;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import com.example.loginmonitoring.config.IntegrationProperties;
import com.example.loginmonitoring.entity.IpInfo;
import com.example.loginmonitoring.entity.IpInfoStatus;
import com.example.loginmonitoring.repository.IpInfoRepository;
import com.example.loginmonitoring.repository.LoginAttemptRepository;

/**
 * Country, city, ISP and "VPN / data centre" flag for an IP address.
 *
 * <p>Uses the free ip-api.com service (no account or key; limit 45 requests per minute).
 * Results are saved in the ip_info table, so each address is looked up only once.
 * Failed logins are looked up in the background (every few seconds) so they never slow down
 * the login page; successful logins are looked up straight away (with a short time limit)
 * because the result is used to spot a login from a new country.
 */
@Service
public class IpIntelService {

    private static final Logger log = LoggerFactory.getLogger(IpIntelService.class);
    private static final Duration KEEP_OK = Duration.ofDays(30);
    private static final Duration RETRY_FAILED = Duration.ofHours(1);

    private final IpInfoRepository ipInfoRepository;
    private final LoginAttemptRepository loginAttemptRepository;
    private final IntegrationProperties properties;
    private final Clock clock;
    private final RestClient restClient;

    private long rateWindowStart;
    private int rateCount;

    public IpIntelService(IpInfoRepository ipInfoRepository, LoginAttemptRepository loginAttemptRepository,
                          IntegrationProperties properties, Clock clock) {
        this.ipInfoRepository = ipInfoRepository;
        this.loginAttemptRepository = loginAttemptRepository;
        this.properties = properties;
        this.clock = clock;
        HttpClient httpClient = HttpClient.newBuilder()
                .connectTimeout(properties.timeout())
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(httpClient);
        factory.setReadTimeout(properties.timeout());
        this.restClient = RestClient.builder()
                .requestFactory(factory)
                .defaultHeader("User-Agent", "LAMS-login-monitor/2.0")
                .build();
        log.info("IP location lookup is {}", properties.ipLookupEnabled() ? "ON (ip-api.com)" : "OFF");
    }

    /** What we know about an IP right now, without calling the outside service. Never null. */
    public IpInfo describe(String ip) {
        return describeAll(List.of(ip)).get(ip);
    }

    /** {@link #describe(String)} for many addresses at once (one database query). */
    public Map<String, IpInfo> describeAll(Collection<String> ips) {
        Map<String, IpInfo> result = new HashMap<>();
        if (ips.isEmpty()) {
            return result;
        }
        for (IpInfo info : ipInfoRepository.findAllById(ips.stream().distinct().toList())) {
            result.put(info.getIpAddress(), info);
        }
        LocalDateTime now = now();
        for (String ip : ips) {
            result.computeIfAbsent(ip, missing -> {
                IpInfoStatus local = IpClassifier.classify(missing);
                return new IpInfo(missing, local == null ? IpInfoStatus.FAILED : local, now);
            });
        }
        return result;
    }

    /**
     * Returns saved details, or looks the IP up now (private addresses are answered locally).
     * Never throws; if the service cannot be reached the result has status FAILED.
     */
    public IpInfo lookupNow(String ip) {
        LocalDateTime now = now();
        Optional<IpInfo> saved = ipInfoRepository.findById(ip);
        if (saved.isPresent() && isFresh(saved.get(), now)) {
            return saved.get();
        }

        IpInfoStatus local = IpClassifier.classify(ip);
        if (local != null) {
            return safeSave(new IpInfo(ip, local, now));
        }
        if (!properties.ipLookupEnabled() || !tryAcquire()) {
            return saved.orElseGet(() -> new IpInfo(ip, IpInfoStatus.FAILED, now));
        }

        IpInfo fetched = fetch(ip, now);
        if (fetched.getStatus() == IpInfoStatus.FAILED && saved.isPresent()
                && saved.get().getStatus() == IpInfoStatus.OK) {
            return saved.get(); // keep the old (good) data if a refresh fails
        }
        return safeSave(fetched);
    }

    /** Two requests may look up the same new IP at once; the second save then loses the race. */
    private IpInfo safeSave(IpInfo info) {
        try {
            return ipInfoRepository.save(info);
        } catch (DataIntegrityViolationException ex) {
            return info;
        }
    }

    /** Background job: looks up recently seen addresses that have no details yet. */
    @Scheduled(initialDelayString = "${app.integrations.ip-lookup-initial-delay-ms:20000}",
               fixedDelayString = "${app.integrations.ip-lookup-interval-ms:15000}")
    public void lookupRecentAddresses() {
        if (!properties.ipLookupEnabled()) {
            return;
        }
        try {
            List<String> pending = loginAttemptRepository.ipsWithoutInfo(now().minusDays(7), Limit.of(10));
            for (String ip : pending) {
                lookupNow(ip);
            }
        } catch (RuntimeException ex) {
            log.warn("Background IP lookup failed: {}", ex.getMessage());
        }
    }

    /** Saves a made-up location for a test address used by the attack simulator. */
    public void saveSimulated(String ip, String country, String countryCode, String city, String isp,
                              boolean proxy, boolean hosting) {
        ipInfoRepository.save(new IpInfo(ip, IpInfoStatus.SIMULATED, now())
                .withLocation(country, countryCode, null, city)
                .withNetwork(isp, isp, "Simulated", proxy, hosting, false));
    }

    private boolean isFresh(IpInfo info, LocalDateTime now) {
        return switch (info.getStatus()) {
            case OK -> info.getLookedUpAt().isAfter(now.minus(KEEP_OK));
            case FAILED -> info.getLookedUpAt().isAfter(now.minus(RETRY_FAILED));
            case PRIVATE, RESERVED, SIMULATED -> true;
        };
    }

    private IpInfo fetch(String ip, LocalDateTime now) {
        try {
            Map<String, Object> body = restClient.get()
                    .uri(properties.ipLookupUrl().replace("{ip}", ip))
                    .retrieve()
                    .body(new ParameterizedTypeReference<Map<String, Object>>() { });
            if (body == null || !"success".equals(body.get("status"))) {
                log.debug("IP lookup for {} returned {}", ip, body);
                return new IpInfo(ip, IpInfoStatus.FAILED, now);
            }
            return new IpInfo(ip, IpInfoStatus.OK, now)
                    .withLocation(text(body, "country"), text(body, "countryCode"), text(body, "regionName"),
                            text(body, "city"))
                    .withNetwork(text(body, "isp"), text(body, "org"), text(body, "as"),
                            flag(body, "proxy"), flag(body, "hosting"), flag(body, "mobile"));
        } catch (RuntimeException ex) {
            log.warn("IP lookup for {} failed: {}", ip, ex.getMessage());
            return new IpInfo(ip, IpInfoStatus.FAILED, now);
        }
    }

    /** Simple per-minute counter so we stay under the free limit of the service. */
    private synchronized boolean tryAcquire() {
        long minute = clock.millis() / 60_000;
        if (minute != rateWindowStart) {
            rateWindowStart = minute;
            rateCount = 0;
        }
        if (rateCount >= properties.ipLookupPerMinute()) {
            return false;
        }
        rateCount++;
        return true;
    }

    private static String text(Map<String, Object> body, String key) {
        Object value = body.get(key);
        return value == null ? null : value.toString();
    }

    private static Boolean flag(Map<String, Object> body, String key) {
        Object value = body.get(key);
        return value instanceof Boolean b ? b : null;
    }

    private LocalDateTime now() {
        return LocalDateTime.now(clock);
    }
}

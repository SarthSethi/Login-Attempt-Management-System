package com.example.loginmonitoring.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Free outside services (prefix "app.integrations"). Each one is optional: when it is switched
 * off or cannot be reached, the application keeps working without that information.
 *
 * @param ipLookupEnabled     look up country / city / ISP of visitor IPs (ip-api.com, no key needed)
 * @param ipLookupUrl         lookup address; "{ip}" is replaced by the IP
 * @param ipLookupPerMinute   stay below the free limit of the service (45 per minute)
 * @param breachCheckEnabled  reject passwords found in known data breaches (Have I Been Pwned)
 * @param breachCheckUrl      range API address; "{prefix}" is replaced by 5 hash characters
 * @param timeout             time limit for one call to an outside service
 * @param retention           login attempts older than this are deleted every night (0 = keep forever, default 180 days)
 */
@ConfigurationProperties(prefix = "app.integrations")
public record IntegrationProperties(
        @DefaultValue("true") boolean ipLookupEnabled,
        @DefaultValue("http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as,mobile,proxy,hosting")
        String ipLookupUrl,
        @DefaultValue("40") int ipLookupPerMinute,
        @DefaultValue("true") boolean breachCheckEnabled,
        @DefaultValue("https://api.pwnedpasswords.com/range/{prefix}") String breachCheckUrl,
        @DefaultValue("2500ms") Duration timeout,
        @DefaultValue("180d") Duration retention) {
}

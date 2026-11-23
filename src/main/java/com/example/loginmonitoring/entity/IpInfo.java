package com.example.loginmonitoring.entity;

import java.time.LocalDateTime;
import java.util.Locale;

import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** Cached location / network details for one IP address. */
@Entity
@Table(name = "ip_info")
public class IpInfo {

    @Id
    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.VARCHAR)
    @Column(nullable = false, length = 20)
    private IpInfoStatus status;

    @Column(length = 80)
    private String country;

    @Column(name = "country_code", length = 2)
    private String countryCode;

    @Column(length = 80)
    private String region;

    @Column(length = 80)
    private String city;

    @Column(length = 120)
    private String isp;

    @Column(length = 120)
    private String org;

    @Column(length = 120)
    private String asn;

    /** Proxy, VPN or Tor exit address. */
    @Column(name = "is_proxy")
    private Boolean proxy;

    /** Hosting provider / data centre address (servers, not home users). */
    @Column(name = "is_hosting")
    private Boolean hosting;

    @Column(name = "is_mobile")
    private Boolean mobile;

    @Column(name = "looked_up_at", nullable = false)
    private LocalDateTime lookedUpAt;

    protected IpInfo() {
        // required by JPA
    }

    public IpInfo(String ipAddress, IpInfoStatus status, LocalDateTime lookedUpAt) {
        this.ipAddress = ipAddress;
        this.status = status;
        this.lookedUpAt = lookedUpAt;
    }

    public IpInfo withLocation(String country, String countryCode, String region, String city) {
        this.country = cut(country, 80);
        this.countryCode = countryCode == null ? null : cut(countryCode.toUpperCase(Locale.ROOT), 2);
        this.region = cut(region, 80);
        this.city = cut(city, 80);
        return this;
    }

    public IpInfo withNetwork(String isp, String org, String asn, Boolean proxy, Boolean hosting, Boolean mobile) {
        this.isp = cut(isp, 120);
        this.org = cut(org, 120);
        this.asn = cut(asn, 120);
        this.proxy = proxy;
        this.hosting = hosting;
        this.mobile = mobile;
        return this;
    }

    /** "Mumbai, India", "Private network", ... */
    public String getLocationLabel() {
        return switch (status) {
            case PRIVATE -> "Private network";
            case RESERVED -> "Reserved / test address";
            case FAILED -> "Unknown";
            case OK, SIMULATED -> {
                if (city != null && !city.isBlank() && country != null && !city.equalsIgnoreCase(country)) {
                    yield city + ", " + country;
                }
                yield country != null ? country : "Unknown";
            }
        };
    }

    /** Flag emoji built from the two-letter country code (no image files needed). */
    public String getFlag() {
        if (countryCode == null || countryCode.length() != 2) {
            return "";
        }
        String code = countryCode.toUpperCase(Locale.ROOT);
        int first = Character.codePointAt(code, 0) - 'A' + 0x1F1E6;
        int second = Character.codePointAt(code, 1) - 'A' + 0x1F1E6;
        return new String(Character.toChars(first)) + new String(Character.toChars(second));
    }

    public boolean isVpnOrHosting() {
        return Boolean.TRUE.equals(proxy) || Boolean.TRUE.equals(hosting);
    }

    private static String cut(String value, int max) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        return trimmed.length() > max ? trimmed.substring(0, max) : trimmed;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public IpInfoStatus getStatus() {
        return status;
    }

    public String getCountry() {
        return country;
    }

    public String getCountryCode() {
        return countryCode;
    }

    public String getRegion() {
        return region;
    }

    public String getCity() {
        return city;
    }

    public String getIsp() {
        return isp;
    }

    public String getOrg() {
        return org;
    }

    public String getAsn() {
        return asn;
    }

    public boolean isProxy() {
        return Boolean.TRUE.equals(proxy);
    }

    public boolean isHosting() {
        return Boolean.TRUE.equals(hosting);
    }

    public boolean isMobile() {
        return Boolean.TRUE.equals(mobile);
    }

    public LocalDateTime getLookedUpAt() {
        return lookedUpAt;
    }
}

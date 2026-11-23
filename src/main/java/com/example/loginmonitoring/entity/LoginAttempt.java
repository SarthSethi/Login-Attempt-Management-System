package com.example.loginmonitoring.entity;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

/**
 * One row per submitted login form. Passwords, cookies and tokens are never stored.
 *
 * <p>Columns added in version 2 (reason, device, risk flags, simulated, reported) are nullable so
 * that Hibernate can add them to an existing database without touching the old rows.
 */
@Entity
@Table(name = "login_attempts", indexes = {
        @Index(name = "idx_login_attempts_ip_time", columnList = "ip_address, attempted_at"),
        @Index(name = "idx_login_attempts_outcome_time", columnList = "outcome, attempted_at"),
        @Index(name = "idx_login_attempts_email_time", columnList = "attempted_email, attempted_at"),
        @Index(name = "idx_login_attempts_time", columnList = "attempted_at")
})
public class LoginAttempt {

    public static final int MAX_EMAIL_LENGTH = 150;
    public static final int MAX_USER_AGENT_LENGTH = 300;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** IPv4 or IPv6 text form (max 45 characters). */
    @Column(name = "ip_address", nullable = false, length = 45)
    private String ipAddress;

    /** The email typed into the form (may not belong to any account). */
    @Column(name = "attempted_email", length = MAX_EMAIL_LENGTH)
    private String attemptedEmail;

    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.VARCHAR)
    @Column(nullable = false, length = 20)
    private LoginOutcome outcome;

    /** UTC. */
    @Column(name = "attempted_at", nullable = false)
    private LocalDateTime attemptedAt;

    /** Why it failed / was rejected (null for successful logins and for rows from version 1). */
    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.VARCHAR)
    @Column(name = "reason", length = 30)
    private AttemptReason reason;

    @Column(name = "user_agent", length = MAX_USER_AGENT_LENGTH)
    private String userAgent;

    @Column(length = 60)
    private String browser;

    @Column(length = 60)
    private String os;

    @Column(name = "device_type", length = 20)
    private String deviceType;

    /** Comma separated {@link RiskFlag} names (successful logins only). */
    @Column(name = "risk_flags", length = 150)
    private String riskFlags;

    @Column(name = "risk_score")
    private Integer riskScore;

    /** Created by the attack simulator (test data). */
    @Column(name = "simulated")
    private Boolean simulated;

    /** The account owner pressed "This wasn't me" for this login. */
    @Column(name = "reported")
    private Boolean reported;

    protected LoginAttempt() {
        // required by JPA
    }

    public LoginAttempt(String ipAddress, String attemptedEmail, LoginOutcome outcome, LocalDateTime attemptedAt) {
        this.ipAddress = ipAddress;
        this.attemptedEmail = attemptedEmail;
        this.outcome = outcome;
        this.attemptedAt = attemptedAt;
    }

    public Long getId() {
        return id;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public String getAttemptedEmail() {
        return attemptedEmail;
    }

    public LoginOutcome getOutcome() {
        return outcome;
    }

    public LocalDateTime getAttemptedAt() {
        return attemptedAt;
    }

    public AttemptReason getReason() {
        return reason;
    }

    public void setReason(AttemptReason reason) {
        this.reason = reason;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }

    public String getBrowser() {
        return browser;
    }

    public void setBrowser(String browser) {
        this.browser = browser;
    }

    public String getOs() {
        return os;
    }

    public void setOs(String os) {
        this.os = os;
    }

    public String getDeviceType() {
        return deviceType;
    }

    public void setDeviceType(String deviceType) {
        this.deviceType = deviceType;
    }

    public String getRiskFlags() {
        return riskFlags;
    }

    public Integer getRiskScore() {
        return riskScore;
    }

    public void setRisk(Collection<RiskFlag> flags) {
        if (flags == null || flags.isEmpty()) {
            this.riskFlags = null;
            this.riskScore = 0;
            return;
        }
        this.riskFlags = String.join(",", flags.stream().map(Enum::name).toList());
        this.riskScore = flags.stream().mapToInt(RiskFlag::getScore).sum();
    }

    /** The risk flags as enum values (unknown names are skipped). */
    public List<RiskFlag> getRiskFlagList() {
        List<RiskFlag> list = new ArrayList<>();
        if (riskFlags == null || riskFlags.isBlank()) {
            return list;
        }
        for (String name : riskFlags.split(",")) {
            try {
                list.add(RiskFlag.valueOf(name.trim()));
            } catch (IllegalArgumentException ignored) {
                // flag from a newer version - ignore
            }
        }
        return list;
    }

    public boolean isSimulated() {
        return Boolean.TRUE.equals(simulated);
    }

    public void setSimulated(boolean simulated) {
        this.simulated = simulated ? Boolean.TRUE : null;
    }

    public boolean isReported() {
        return Boolean.TRUE.equals(reported);
    }

    public void setReported(boolean reported) {
        this.reported = reported;
    }

    /** "Chrome on Windows (Desktop)" or "-" if unknown. */
    public String getDeviceLabel() {
        if (browser == null && os == null) {
            return "-";
        }
        StringBuilder text = new StringBuilder(browser == null ? "Unknown browser" : browser);
        if (os != null) {
            text.append(" on ").append(os);
        }
        return text.toString();
    }

    @Override
    public String toString() {
        return "LoginAttempt[id=" + id + ", ip=" + ipAddress + ", email=" + attemptedEmail
                + ", outcome=" + outcome + ", reason=" + reason + ", at=" + attemptedAt + "]";
    }
}

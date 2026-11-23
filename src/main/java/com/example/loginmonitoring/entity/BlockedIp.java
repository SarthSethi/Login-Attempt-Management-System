package com.example.loginmonitoring.entity;

import java.time.LocalDateTime;

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
 * One row per blocking event. Rows are never deleted, so expired blocks remain as history.
 * An IP is blocked only while {@code expiresAt} is in the future. Unblocking early simply moves
 * {@code expiresAt} to "now" and records who lifted it.
 */
@Entity
@Table(name = "blocked_ips", indexes = {
        @Index(name = "idx_blocked_ips_ip_expires", columnList = "ip_address, expires_at"),
        @Index(name = "idx_blocked_ips_expires", columnList = "expires_at")
})
public class BlockedIp {

    public static final String REASON_REPEATED_FAILURES = "Repeated failed login attempts";

    /** Expiry used for permanent bans (fits in a MySQL DATETIME). */
    public static final LocalDateTime PERMANENT_EXPIRY = LocalDateTime.of(2999, 12, 31, 23, 59, 59);

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "ip_address", nullable = false, length = 45)
    private String ipAddress;

    /** UTC. */
    @Column(name = "blocked_at", nullable = false)
    private LocalDateTime blockedAt;

    /** UTC. */
    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(nullable = false, length = 255)
    private String reason;

    /** Null on rows from version 1, which were all automatic. */
    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.VARCHAR)
    @Column(length = 20)
    private BlockSource source;

    /** 1 = first block, 2 = second block within 24 hours, ... (automatic blocks only). */
    @Column(name = "block_level")
    private Integer level;

    @Column(name = "created_by", length = 150)
    private String createdBy;

    @Column(name = "lifted_at")
    private LocalDateTime liftedAt;

    @Column(name = "lifted_by", length = 150)
    private String liftedBy;

    @Column(name = "simulated")
    private Boolean simulated;

    protected BlockedIp() {
        // required by JPA
    }

    public BlockedIp(String ipAddress, LocalDateTime blockedAt, LocalDateTime expiresAt, String reason) {
        this.ipAddress = ipAddress;
        this.blockedAt = blockedAt;
        this.expiresAt = expiresAt;
        this.reason = reason;
        this.source = BlockSource.AUTOMATIC;
        this.level = 1;
    }

    /** True while the block has not yet expired. */
    public boolean isActiveAt(LocalDateTime now) {
        return expiresAt.isAfter(now);
    }

    public boolean isPermanent() {
        return !expiresAt.isBefore(PERMANENT_EXPIRY.minusYears(1));
    }

    /** Ends the block now (keeps the row as history). */
    public void lift(LocalDateTime now, String by) {
        if (expiresAt.isAfter(now)) {
            expiresAt = now;
        }
        liftedAt = now;
        liftedBy = by;
    }

    public Long getId() {
        return id;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public LocalDateTime getBlockedAt() {
        return blockedAt;
    }

    public LocalDateTime getExpiresAt() {
        return expiresAt;
    }

    public String getReason() {
        return reason;
    }

    public BlockSource getSource() {
        return source == null ? BlockSource.AUTOMATIC : source;
    }

    public void setSource(BlockSource source) {
        this.source = source;
    }

    public int getLevel() {
        return level == null ? 1 : level;
    }

    public void setLevel(int level) {
        this.level = level;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    public LocalDateTime getLiftedAt() {
        return liftedAt;
    }

    public String getLiftedBy() {
        return liftedBy;
    }

    public boolean isSimulated() {
        return Boolean.TRUE.equals(simulated);
    }

    public void setSimulated(boolean simulated) {
        this.simulated = simulated ? Boolean.TRUE : null;
    }
}

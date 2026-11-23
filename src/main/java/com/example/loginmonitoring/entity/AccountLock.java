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
 * A temporary lock on an email address (account), created by a detection rule.
 * <ul>
 *   <li>{@link LockType#ACCOUNT_IP}: the account is locked for ONE IP address only.</li>
 *   <li>{@link LockType#ACCOUNT}: the account is locked for every IP it has never logged in from;
 *       the owner can still log in from their usual network.</li>
 * </ul>
 * Works for any email, existing or not, so a lock never reveals whether an account exists.
 */
@Entity
@Table(name = "account_locks", indexes = {
        @Index(name = "idx_account_locks_email_expires", columnList = "email, expires_at"),
        @Index(name = "idx_account_locks_expires", columnList = "expires_at")
})
public class AccountLock {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = LoginAttempt.MAX_EMAIL_LENGTH)
    private String email;

    /** Set for ACCOUNT_IP locks, null for ACCOUNT locks. */
    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.VARCHAR)
    @Column(name = "lock_type", nullable = false, length = 20)
    private LockType type;

    @Column(name = "locked_at", nullable = false)
    private LocalDateTime lockedAt;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(nullable = false, length = 255)
    private String reason;

    @Column(name = "lifted_at")
    private LocalDateTime liftedAt;

    @Column(name = "lifted_by", length = 150)
    private String liftedBy;

    @Column(name = "simulated")
    private Boolean simulated;

    protected AccountLock() {
        // required by JPA
    }

    public AccountLock(String email, String ipAddress, LockType type, LocalDateTime lockedAt,
                       LocalDateTime expiresAt, String reason) {
        this.email = email;
        this.ipAddress = ipAddress;
        this.type = type;
        this.lockedAt = lockedAt;
        this.expiresAt = expiresAt;
        this.reason = reason;
    }

    public boolean isActiveAt(LocalDateTime now) {
        return expiresAt.isAfter(now);
    }

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

    public String getEmail() {
        return email;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public LockType getType() {
        return type;
    }

    public LocalDateTime getLockedAt() {
        return lockedAt;
    }

    public LocalDateTime getExpiresAt() {
        return expiresAt;
    }

    public String getReason() {
        return reason;
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

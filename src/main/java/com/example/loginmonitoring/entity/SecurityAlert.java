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

/** Something the administrator should look at, raised by a detection rule or by a user report. */
@Entity
@Table(name = "security_alerts", indexes = {
        @Index(name = "idx_security_alerts_time", columnList = "created_at"),
        @Index(name = "idx_security_alerts_ack", columnList = "acknowledged, created_at")
})
public class SecurityAlert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.VARCHAR)
    @Column(name = "alert_type", nullable = false, length = 30)
    private AlertType type;

    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.VARCHAR)
    @Column(nullable = false, length = 10)
    private AlertSeverity severity;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(length = LoginAttempt.MAX_EMAIL_LENGTH)
    private String email;

    @Column(nullable = false, length = 500)
    private String message;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private boolean acknowledged;

    @Column(name = "acknowledged_by", length = 150)
    private String acknowledgedBy;

    @Column(name = "acknowledged_at")
    private LocalDateTime acknowledgedAt;

    @Column(name = "simulated")
    private Boolean simulated;

    protected SecurityAlert() {
        // required by JPA
    }

    public SecurityAlert(AlertType type, AlertSeverity severity, String ipAddress, String email,
                         String message, LocalDateTime createdAt) {
        this.type = type;
        this.severity = severity;
        this.ipAddress = ipAddress;
        this.email = email;
        this.message = message.length() > 500 ? message.substring(0, 500) : message;
        this.createdAt = createdAt;
    }

    public void acknowledge(String by, LocalDateTime now) {
        acknowledged = true;
        acknowledgedBy = by;
        acknowledgedAt = now;
    }

    public Long getId() {
        return id;
    }

    public AlertType getType() {
        return type;
    }

    public AlertSeverity getSeverity() {
        return severity;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public String getEmail() {
        return email;
    }

    public String getMessage() {
        return message;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public boolean isAcknowledged() {
        return acknowledged;
    }

    public String getAcknowledgedBy() {
        return acknowledgedBy;
    }

    public LocalDateTime getAcknowledgedAt() {
        return acknowledgedAt;
    }

    public boolean isSimulated() {
        return Boolean.TRUE.equals(simulated);
    }

    public void setSimulated(boolean simulated) {
        this.simulated = simulated ? Boolean.TRUE : null;
    }
}

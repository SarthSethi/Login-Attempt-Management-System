package com.example.loginmonitoring.entity;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * An IP address or CIDR range (for example a college network) that the automatic rules never
 * block. Attempts from it are still recorded and account protection still applies.
 */
@Entity
@Table(name = "ip_allowlist")
public class IpAllowlistEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 50)
    private String cidr;

    @Column(length = 150)
    private String note;

    @Column(name = "created_by", length = 150)
    private String createdBy;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    protected IpAllowlistEntry() {
        // required by JPA
    }

    public IpAllowlistEntry(String cidr, String note, String createdBy, LocalDateTime createdAt) {
        this.cidr = cidr;
        this.note = note;
        this.createdBy = createdBy;
        this.createdAt = createdAt;
    }

    public Long getId() {
        return id;
    }

    public String getCidr() {
        return cidr;
    }

    public String getNote() {
        return note;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }
}

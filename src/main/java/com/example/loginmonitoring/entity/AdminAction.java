package com.example.loginmonitoring.entity;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

/** Audit log: one row for every change an administrator makes. */
@Entity
@Table(name = "admin_actions", indexes = @Index(name = "idx_admin_actions_time", columnList = "created_at"))
public class AdminAction {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "admin_email", nullable = false, length = 150)
    private String adminEmail;

    @Column(nullable = false, length = 60)
    private String action;

    @Column(length = 200)
    private String target;

    @Column(length = 300)
    private String detail;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    protected AdminAction() {
        // required by JPA
    }

    public AdminAction(String adminEmail, String action, String target, String detail, LocalDateTime createdAt) {
        this.adminEmail = adminEmail;
        this.action = action;
        this.target = target == null || target.length() <= 200 ? target : target.substring(0, 200);
        this.detail = detail == null || detail.length() <= 300 ? detail : detail.substring(0, 300);
        this.createdAt = createdAt;
    }

    public Long getId() {
        return id;
    }

    public String getAdminEmail() {
        return adminEmail;
    }

    public String getAction() {
        return action;
    }

    public String getTarget() {
        return target;
    }

    public String getDetail() {
        return detail;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }
}

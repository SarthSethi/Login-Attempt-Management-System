package com.example.loginmonitoring.service;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.loginmonitoring.entity.AdminAction;
import com.example.loginmonitoring.repository.AdminActionRepository;

/** Writes the audit log of administrator actions. */
@Service
public class AdminAuditService {

    private static final Logger log = LoggerFactory.getLogger(AdminAuditService.class);

    private final AdminActionRepository repository;
    private final Clock clock;

    public AdminAuditService(AdminActionRepository repository, Clock clock) {
        this.repository = repository;
        this.clock = clock;
    }

    @Transactional
    public void log(String adminEmail, String action, String target, String detail) {
        log.info("Admin {} - {} {} {}", adminEmail, action, target == null ? "" : target, detail == null ? "" : detail);
        repository.save(new AdminAction(adminEmail, action, target, detail, LocalDateTime.now(clock)));
    }

    @Transactional(readOnly = true)
    public List<AdminAction> recent(int max) {
        return repository.findAllByOrderByCreatedAtDescIdDesc(Limit.of(max));
    }
}

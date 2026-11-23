package com.example.loginmonitoring.service;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.loginmonitoring.entity.AlertSeverity;
import com.example.loginmonitoring.entity.AlertType;
import com.example.loginmonitoring.entity.SecurityAlert;
import com.example.loginmonitoring.repository.SecurityAlertRepository;

/** Creates and lists security alerts for the administrator. */
@Service
public class AlertService {

    private static final Logger log = LoggerFactory.getLogger(AlertService.class);

    private final SecurityAlertRepository alertRepository;
    private final Clock clock;

    public AlertService(SecurityAlertRepository alertRepository, Clock clock) {
        this.alertRepository = alertRepository;
        this.clock = clock;
    }

    @Transactional
    public SecurityAlert raise(AlertType type, AlertSeverity severity, String ip, String email, String message,
                               boolean simulated) {
        SecurityAlert alert = new SecurityAlert(type, severity, ip, email, message, LocalDateTime.now(clock));
        alert.setSimulated(simulated);
        log.warn("ALERT [{}] {}: {}", severity, type, message);
        return alertRepository.save(alert);
    }

    @Transactional(readOnly = true)
    public long countOpen() {
        return alertRepository.countByAcknowledgedFalse();
    }

    @Transactional(readOnly = true)
    public List<SecurityAlert> recent(int max) {
        return alertRepository.findAllByOrderByCreatedAtDescIdDesc(Limit.of(max));
    }

    @Transactional(readOnly = true)
    public List<SecurityAlert> open(int max) {
        return alertRepository.findByAcknowledgedFalseOrderByCreatedAtDescIdDesc(Limit.of(max));
    }

    @Transactional(readOnly = true)
    public List<SecurityAlert> forIp(String ip, int max) {
        return alertRepository.findByIpAddressOrderByCreatedAtDescIdDesc(ip, Limit.of(max));
    }

    @Transactional(readOnly = true)
    public List<SecurityAlert> forEmail(String email, int max) {
        return alertRepository.findByEmailOrderByCreatedAtDescIdDesc(email, Limit.of(max));
    }

    @Transactional
    public boolean acknowledge(long id, String by) {
        return alertRepository.findById(id).map(alert -> {
            alert.acknowledge(by, LocalDateTime.now(clock));
            return true;
        }).orElse(false);
    }

    @Transactional
    public int acknowledgeAll(String by) {
        List<SecurityAlert> open = alertRepository.findByAcknowledgedFalse();
        LocalDateTime now = LocalDateTime.now(clock);
        open.forEach(alert -> alert.acknowledge(by, now));
        return open.size();
    }
}

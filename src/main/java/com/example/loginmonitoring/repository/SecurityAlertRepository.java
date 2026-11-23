package com.example.loginmonitoring.repository;

import java.util.List;

import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import com.example.loginmonitoring.entity.SecurityAlert;

public interface SecurityAlertRepository extends JpaRepository<SecurityAlert, Long> {

    long countByAcknowledgedFalse();

    List<SecurityAlert> findAllByOrderByCreatedAtDescIdDesc(Limit limit);

    List<SecurityAlert> findByAcknowledgedFalseOrderByCreatedAtDescIdDesc(Limit limit);

    List<SecurityAlert> findByIpAddressOrderByCreatedAtDescIdDesc(String ipAddress, Limit limit);

    List<SecurityAlert> findByEmailOrderByCreatedAtDescIdDesc(String email, Limit limit);

    List<SecurityAlert> findByAcknowledgedFalse();

    @Modifying
    @Query("delete from SecurityAlert a where a.simulated = true")
    int deleteSimulated();
}

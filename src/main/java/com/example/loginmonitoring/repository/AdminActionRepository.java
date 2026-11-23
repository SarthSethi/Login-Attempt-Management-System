package com.example.loginmonitoring.repository;

import java.util.List;

import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.JpaRepository;

import com.example.loginmonitoring.entity.AdminAction;

public interface AdminActionRepository extends JpaRepository<AdminAction, Long> {

    List<AdminAction> findAllByOrderByCreatedAtDescIdDesc(Limit limit);
}

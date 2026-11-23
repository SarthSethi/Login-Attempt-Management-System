package com.example.loginmonitoring.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.loginmonitoring.entity.IpAllowlistEntry;

public interface IpAllowlistRepository extends JpaRepository<IpAllowlistEntry, Long> {

    List<IpAllowlistEntry> findAllByOrderByCreatedAtDesc();

    boolean existsByCidr(String cidr);
}

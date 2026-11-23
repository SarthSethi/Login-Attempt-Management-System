package com.example.loginmonitoring.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import com.example.loginmonitoring.entity.IpInfo;

public interface IpInfoRepository extends JpaRepository<IpInfo, String> {

    @Modifying
    @Query("delete from IpInfo i where i.status = com.example.loginmonitoring.entity.IpInfoStatus.SIMULATED")
    int deleteSimulated();
}

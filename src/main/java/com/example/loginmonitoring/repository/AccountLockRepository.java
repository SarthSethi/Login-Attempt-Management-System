package com.example.loginmonitoring.repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import com.example.loginmonitoring.entity.AccountLock;
import com.example.loginmonitoring.entity.LockType;

public interface AccountLockRepository extends JpaRepository<AccountLock, Long> {

    List<AccountLock> findByEmailAndExpiresAtAfter(String email, LocalDateTime now);

    Optional<AccountLock> findFirstByEmailAndIpAddressAndTypeOrderByLockedAtDescIdDesc(String email, String ip,
                                                                                       LockType type);

    Optional<AccountLock> findFirstByEmailAndTypeOrderByLockedAtDescIdDesc(String email, LockType type);

    List<AccountLock> findByExpiresAtAfterOrderByLockedAtDesc(LocalDateTime now);

    List<AccountLock> findAllByOrderByLockedAtDescIdDesc(Limit limit);

    List<AccountLock> findByIpAddressOrderByLockedAtDescIdDesc(String ipAddress, Limit limit);

    long countByExpiresAtAfter(LocalDateTime now);

    @Modifying
    @Query("delete from AccountLock l where l.simulated = true")
    int deleteSimulated();
}

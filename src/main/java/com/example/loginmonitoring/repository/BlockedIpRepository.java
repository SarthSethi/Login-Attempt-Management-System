package com.example.loginmonitoring.repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.example.loginmonitoring.entity.BlockSource;
import com.example.loginmonitoring.entity.BlockedIp;

public interface BlockedIpRepository extends JpaRepository<BlockedIp, Long> {

    /** The block that is still running for this IP, if any (expires_at in the future). */
    Optional<BlockedIp> findFirstByIpAddressAndExpiresAtAfterOrderByExpiresAtDesc(String ipAddress, LocalDateTime now);

    /** All running blocks for this IP. */
    List<BlockedIp> findByIpAddressAndExpiresAtAfter(String ipAddress, LocalDateTime now);

    /** The most recent block of this IP, active or expired. */
    Optional<BlockedIp> findFirstByIpAddressOrderByBlockedAtDescIdDesc(String ipAddress);

    List<BlockedIp> findByIpAddressOrderByBlockedAtDescIdDesc(String ipAddress, Limit limit);

    /** Earlier automatic blocks (for repeat-offender escalation). Old rows have source = null. */
    @Query("""
            select count(b) from BlockedIp b
            where b.ipAddress = :ip and b.blockedAt > :after
              and (b.source is null or b.source = :source)
            """)
    long countBlocksSince(@Param("ip") String ip, @Param("after") LocalDateTime after,
                          @Param("source") BlockSource source);

    @Query("select count(distinct b.ipAddress) from BlockedIp b where b.expiresAt > :now")
    long countActiveBlockedIps(@Param("now") LocalDateTime now);

    List<BlockedIp> findByExpiresAtAfterOrderByBlockedAtDesc(LocalDateTime now);

    /** Admin table. A null ip means "no filter". */
    @Query("""
            select b from BlockedIp b
            where (:ip is null or b.ipAddress like concat('%', :ip, '%'))
            order by b.blockedAt desc, b.id desc
            """)
    List<BlockedIp> search(@Param("ip") String ip, Limit limit);

    @Modifying
    @Query("delete from BlockedIp b where b.simulated = true")
    int deleteSimulated();
}

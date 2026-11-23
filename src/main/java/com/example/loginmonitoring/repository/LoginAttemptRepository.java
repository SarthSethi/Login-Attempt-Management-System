package com.example.loginmonitoring.repository;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Limit;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.example.loginmonitoring.dto.KeyCount;
import com.example.loginmonitoring.dto.TimeOutcome;
import com.example.loginmonitoring.entity.LoginAttempt;
import com.example.loginmonitoring.entity.LoginOutcome;

/**
 * All queries are either derived from the method name or written in JPQL with
 * named parameters, so user input is always sent to MySQL as a bound parameter,
 * never concatenated into SQL text.
 */
public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, Long> {

    long countByOutcome(LoginOutcome outcome);

    long countByAttemptedAtAfter(LocalDateTime after);

    long countByOutcomeAndAttemptedAtAfter(LoginOutcome outcome, LocalDateTime after);

    // ---------- detection rules ----------

    /** FAILED attempts from one IP (any email) after a given time. */
    long countByIpAddressAndOutcomeAndAttemptedAtAfter(String ipAddress, LoginOutcome outcome, LocalDateTime after);

    /** FAILED attempts for one email from one IP after a given time. */
    long countByIpAddressAndAttemptedEmailAndOutcomeAndAttemptedAtAfter(String ipAddress, String email,
                                                                       LoginOutcome outcome, LocalDateTime after);

    /** FAILED attempts for one email (any IP) after a given time. */
    long countByAttemptedEmailAndOutcomeAndAttemptedAtAfter(String email, LoginOutcome outcome, LocalDateTime after);

    @Query("""
            select count(distinct a.attemptedEmail) from LoginAttempt a
            where a.ipAddress = :ip and a.outcome = :outcome and a.attemptedAt > :after
            """)
    long countDistinctEmailsFromIp(@Param("ip") String ip, @Param("outcome") LoginOutcome outcome,
                                   @Param("after") LocalDateTime after);

    @Query("""
            select count(distinct a.ipAddress) from LoginAttempt a
            where a.attemptedEmail = :email and a.outcome = :outcome and a.attemptedAt > :after
            """)
    long countDistinctIpsForEmail(@Param("email") String email, @Param("outcome") LoginOutcome outcome,
                                  @Param("after") LocalDateTime after);

    /** Has this account ever logged in successfully from this IP (after a given time)? */
    boolean existsByAttemptedEmailAndIpAddressAndOutcomeAndAttemptedAtAfter(String email, String ipAddress,
                                                                          LoginOutcome outcome, LocalDateTime after);

    Optional<LoginAttempt> findFirstByAttemptedEmailAndIpAddressAndOutcomeOrderByAttemptedAtDescIdDesc(
            String email, String ipAddress, LoginOutcome outcome);

    /** Successful logins of one account, newest first (for "new device / new country" checks). */
    List<LoginAttempt> findByAttemptedEmailAndOutcomeAndAttemptedAtAfterOrderByAttemptedAtDescIdDesc(
            String email, LoginOutcome outcome, LocalDateTime after, Limit limit);

    /** The successful login of this account just before a given attempt id. */
    Optional<LoginAttempt> findFirstByAttemptedEmailAndOutcomeAndIdLessThanOrderByIdDesc(String email,
                                                                                         LoginOutcome outcome, Long id);

    /** Latest two successful logins of a user: [0] is the current login, [1] the previous one. */
    List<LoginAttempt> findTop2ByAttemptedEmailAndOutcomeOrderByAttemptedAtDescIdDesc(String email, LoginOutcome outcome);

    // ---------- user activity page ----------

    List<LoginAttempt> findByAttemptedEmailOrderByAttemptedAtDescIdDesc(String email, Limit limit);

    @Query("""
            select count(a) from LoginAttempt a
            where a.attemptedEmail = :email and a.outcome <> com.example.loginmonitoring.entity.LoginOutcome.SUCCESS
              and a.attemptedAt > :after
            """)
    long countUnsuccessfulForEmailAfter(@Param("email") String email, @Param("after") LocalDateTime after);

    // ---------- admin pages ----------

    /** Attempt log with optional filters (null = no filter). */
    @Query("""
            select a from LoginAttempt a
            where (:outcome is null or a.outcome = :outcome)
              and (:ip is null or a.ipAddress like concat('%', :ip, '%'))
              and (:email is null or a.attemptedEmail like concat('%', :email, '%'))
            order by a.attemptedAt desc, a.id desc
            """)
    Page<LoginAttempt> search(@Param("outcome") LoginOutcome outcome, @Param("ip") String ip,
                              @Param("email") String email, Pageable pageable);

    List<LoginAttempt> findByIpAddressOrderByAttemptedAtDescIdDesc(String ipAddress, Limit limit);

    List<LoginAttempt> findByIdGreaterThanOrderByIdDesc(Long id, Limit limit);

    List<LoginAttempt> findAllByOrderByIdDesc(Limit limit);

    long countByIpAddress(String ipAddress);

    long countByIpAddressAndOutcome(String ipAddress, LoginOutcome outcome);

    @Query("select min(a.attemptedAt) from LoginAttempt a where a.ipAddress = :ip")
    LocalDateTime firstSeen(@Param("ip") String ip);

    @Query("select max(a.attemptedAt) from LoginAttempt a where a.ipAddress = :ip")
    LocalDateTime lastSeen(@Param("ip") String ip);

    @Query("""
            select new com.example.loginmonitoring.dto.TimeOutcome(a.attemptedAt, a.outcome)
            from LoginAttempt a where a.attemptedAt >= :since
            """)
    List<TimeOutcome> timeline(@Param("since") LocalDateTime since, Limit limit);

    /** IPs with the most unsuccessful attempts since a given time. */
    @Query("""
            select new com.example.loginmonitoring.dto.KeyCount(a.ipAddress, count(a))
            from LoginAttempt a
            where a.outcome <> com.example.loginmonitoring.entity.LoginOutcome.SUCCESS and a.attemptedAt >= :since
            group by a.ipAddress order by count(a) desc
            """)
    List<KeyCount> topUnsuccessfulIps(@Param("since") LocalDateTime since, Limit limit);

    /** Emails with the most FAILED attempts since a given time. */
    @Query("""
            select new com.example.loginmonitoring.dto.KeyCount(a.attemptedEmail, count(a))
            from LoginAttempt a
            where a.outcome = com.example.loginmonitoring.entity.LoginOutcome.FAILED and a.attemptedAt >= :since
              and a.attemptedEmail is not null
            group by a.attemptedEmail order by count(a) desc
            """)
    List<KeyCount> topTargetedEmails(@Param("since") LocalDateTime since, Limit limit);

    /** All IPs seen since a given time with their number of attempts (for the country chart). */
    @Query("""
            select new com.example.loginmonitoring.dto.KeyCount(a.ipAddress, count(a))
            from LoginAttempt a where a.attemptedAt >= :since
            group by a.ipAddress
            """)
    List<KeyCount> attemptsPerIp(@Param("since") LocalDateTime since);

    /** Emails tried from one IP with how often. */
    @Query("""
            select new com.example.loginmonitoring.dto.KeyCount(a.attemptedEmail, count(a))
            from LoginAttempt a where a.ipAddress = :ip and a.attemptedEmail is not null
            group by a.attemptedEmail order by count(a) desc
            """)
    List<KeyCount> emailsTriedFromIp(@Param("ip") String ip, Limit limit);

    /** Recently seen IPs that have no ip_info row yet (for the background location lookup). */
    @Query("""
            select distinct a.ipAddress from LoginAttempt a
            where a.attemptedAt >= :since
              and a.ipAddress not in (select i.ipAddress from IpInfo i)
            """)
    List<String> ipsWithoutInfo(@Param("since") LocalDateTime since, Limit limit);

    /** FAILED attempts per user email since a given time (for the Users page). */
    @Query("""
            select new com.example.loginmonitoring.dto.KeyCount(a.attemptedEmail, count(a))
            from LoginAttempt a
            where a.outcome = com.example.loginmonitoring.entity.LoginOutcome.FAILED and a.attemptedAt >= :since
              and a.attemptedEmail in :emails
            group by a.attemptedEmail
            """)
    List<KeyCount> failuresForEmails(@Param("emails") Collection<String> emails, @Param("since") LocalDateTime since);

    // ---------- clean-up ----------

    @Modifying
    @Query("delete from LoginAttempt a where a.simulated = true")
    int deleteSimulated();

    @Modifying
    @Query("delete from LoginAttempt a where a.attemptedAt < :before")
    int deleteOlderThan(@Param("before") LocalDateTime before);
}

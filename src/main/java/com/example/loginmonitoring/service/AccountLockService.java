package com.example.loginmonitoring.service;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.loginmonitoring.config.LoginSecurityProperties;
import com.example.loginmonitoring.entity.AccountLock;
import com.example.loginmonitoring.entity.LockType;
import com.example.loginmonitoring.repository.AccountLockRepository;

/** Temporary locks on accounts (see {@link AccountLock}). */
@Service
public class AccountLockService {

    private static final Logger log = LoggerFactory.getLogger(AccountLockService.class);

    private final AccountLockRepository repository;
    private final LoginSecurityProperties properties;
    private final Clock clock;

    public AccountLockService(AccountLockRepository repository, LoginSecurityProperties properties, Clock clock) {
        this.repository = repository;
        this.properties = properties;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public List<AccountLock> activeLocks(String email) {
        if (email == null) {
            return List.of();
        }
        return repository.findByEmailAndExpiresAtAfter(email, now());
    }

    @Transactional(readOnly = true)
    public Optional<AccountLock> latestPairLock(String email, String ip) {
        return repository.findFirstByEmailAndIpAddressAndTypeOrderByLockedAtDescIdDesc(email, ip, LockType.ACCOUNT_IP);
    }

    @Transactional(readOnly = true)
    public Optional<AccountLock> latestAccountLock(String email) {
        return repository.findFirstByEmailAndTypeOrderByLockedAtDescIdDesc(email, LockType.ACCOUNT);
    }

    @Transactional
    public AccountLock lockPair(String email, String ip, String reason, boolean simulated) {
        return save(new AccountLock(email, ip, LockType.ACCOUNT_IP, now(), now().plus(properties.blockDuration()),
                reason), simulated);
    }

    @Transactional
    public AccountLock lockAccount(String email, String reason, boolean simulated) {
        return save(new AccountLock(email, null, LockType.ACCOUNT, now(), now().plus(properties.blockDuration()),
                reason), simulated);
    }

    @Transactional
    public boolean lift(long id, String by) {
        return repository.findById(id).map(lock -> {
            lock.lift(now(), by);
            return true;
        }).orElse(false);
    }

    @Transactional
    public int liftAllFor(String email, String by) {
        List<AccountLock> active = repository.findByEmailAndExpiresAtAfter(email, now());
        active.forEach(lock -> lock.lift(now(), by));
        return active.size();
    }

    @Transactional(readOnly = true)
    public List<AccountLock> allActive() {
        return repository.findByExpiresAtAfterOrderByLockedAtDesc(now());
    }

    @Transactional(readOnly = true)
    public List<AccountLock> recent(int max) {
        return repository.findAllByOrderByLockedAtDescIdDesc(Limit.of(max));
    }

    @Transactional(readOnly = true)
    public List<AccountLock> forIp(String ip, int max) {
        return repository.findByIpAddressOrderByLockedAtDescIdDesc(ip, Limit.of(max));
    }

    @Transactional(readOnly = true)
    public long countActive() {
        return repository.countByExpiresAtAfter(now());
    }

    private AccountLock save(AccountLock lock, boolean simulated) {
        lock.setSimulated(simulated);
        String reason = lock.getReason();
        log.warn("Locked account {} ({}{}) until {}: {}", lock.getEmail(), lock.getType(),
                lock.getIpAddress() == null ? "" : " from " + lock.getIpAddress(), lock.getExpiresAt(), reason);
        return repository.save(lock);
    }

    private LocalDateTime now() {
        return LocalDateTime.now(clock);
    }
}

package com.example.loginmonitoring.service;

import java.time.Clock;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.loginmonitoring.config.LoginSecurityProperties;
import com.example.loginmonitoring.dto.BlockedIpView;
import com.example.loginmonitoring.entity.BlockSource;
import com.example.loginmonitoring.entity.BlockedIp;
import com.example.loginmonitoring.repository.BlockedIpRepository;

/**
 * Creates IP blocks and answers "is this IP blocked right now?".
 *
 * <p>There is no background job that removes blocks. A block simply stops counting once
 * {@code expires_at} is in the past, because every check compares {@code expires_at}
 * with the current time. Old rows stay in the table as history.
 *
 * <p>Repeat offenders: every automatic block within 24 hours of an earlier one lasts longer
 * (15 minutes, then 1 hour, then 24 hours by default).
 */
@Service
public class BlockedIpService {

    private static final Logger log = LoggerFactory.getLogger(BlockedIpService.class);

    private final BlockedIpRepository blockedIpRepository;
    private final LoginSecurityProperties properties;
    private final Clock clock;

    public BlockedIpService(BlockedIpRepository blockedIpRepository, LoginSecurityProperties properties, Clock clock) {
        this.blockedIpRepository = blockedIpRepository;
        this.properties = properties;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public Optional<BlockedIp> findActiveBlock(String ipAddress) {
        return blockedIpRepository.findFirstByIpAddressAndExpiresAtAfterOrderByExpiresAtDesc(ipAddress, now());
    }

    @Transactional(readOnly = true)
    public boolean isBlocked(String ipAddress) {
        return findActiveBlock(ipAddress).isPresent();
    }

    @Transactional(readOnly = true)
    public Optional<BlockedIp> findLatestBlock(String ipAddress) {
        return blockedIpRepository.findFirstByIpAddressOrderByBlockedAtDescIdDesc(ipAddress);
    }

    /** Automatic block by a detection rule, with repeat-offender escalation. */
    @Transactional
    public BlockedIp blockAutomatically(String ipAddress, String reason, boolean simulated) {
        LocalDateTime blockedAt = now();
        int level = (int) blockedIpRepository.countBlocksSince(ipAddress, blockedAt.minus(properties.repeatWindow()),
                BlockSource.AUTOMATIC) + 1;
        Duration duration = properties.blockDurationForLevel(level);
        BlockedIp block = new BlockedIp(ipAddress, blockedAt, blockedAt.plus(duration), cut(reason));
        block.setLevel(level);
        block.setSimulated(simulated);
        log.warn("Blocked IP {} for {} (level {}): {}", ipAddress, duration, level, reason);
        return blockedIpRepository.save(block);
    }

    /** Block created by an administrator or by a user report. {@code duration == null} = permanent. */
    @Transactional
    public BlockedIp blockManually(String ipAddress, Duration duration, String reason, BlockSource source,
                                   String by, boolean simulated) {
        LocalDateTime blockedAt = now();
        LocalDateTime expiresAt = duration == null ? BlockedIp.PERMANENT_EXPIRY : blockedAt.plus(duration);
        BlockedIp block = new BlockedIp(ipAddress, blockedAt, expiresAt, cut(reason));
        block.setSource(source);
        block.setCreatedBy(by);
        block.setSimulated(simulated);
        log.warn("Blocked IP {} until {} by {}: {}", ipAddress, expiresAt, by, reason);
        return blockedIpRepository.save(block);
    }

    /** Ends every running block of this IP. */
    @Transactional
    public int unblock(String ipAddress, String by) {
        LocalDateTime now = now();
        List<BlockedIp> active = blockedIpRepository.findByIpAddressAndExpiresAtAfter(ipAddress, now);
        active.forEach(block -> block.lift(now, by));
        return active.size();
    }

    @Transactional(readOnly = true)
    public long countActiveBlockedIps() {
        return blockedIpRepository.countActiveBlockedIps(now());
    }

    @Transactional(readOnly = true)
    public List<BlockedIpView> activeBlocks() {
        LocalDateTime now = now();
        return blockedIpRepository.findByExpiresAtAfterOrderByBlockedAtDesc(now).stream()
                .map(block -> toView(block, now)).toList();
    }

    /** Newest blocks first. {@code ipSearch} may be null. */
    @Transactional(readOnly = true)
    public List<BlockedIpView> search(String ipSearch, int maxRows) {
        LocalDateTime now = now();
        return blockedIpRepository.search(ipSearch, Limit.of(maxRows)).stream()
                .map(block -> toView(block, now))
                .toList();
    }

    @Transactional(readOnly = true)
    public List<BlockedIpView> historyFor(String ipAddress, int maxRows) {
        LocalDateTime now = now();
        return blockedIpRepository.findByIpAddressOrderByBlockedAtDescIdDesc(ipAddress, Limit.of(maxRows)).stream()
                .map(block -> toView(block, now)).toList();
    }

    private static BlockedIpView toView(BlockedIp block, LocalDateTime now) {
        boolean active = block.isActiveAt(now);
        String remaining;
        if (!active) {
            remaining = "-";
        } else if (block.isPermanent()) {
            remaining = "Permanent";
        } else {
            remaining = formatRemaining(Duration.between(now, block.getExpiresAt()));
        }
        return new BlockedIpView(block.getId(), block.getIpAddress(), block.getBlockedAt(), block.getExpiresAt(),
                remaining, active, block.getReason(), block.getSource(), block.getLevel(), block.isPermanent(),
                block.isSimulated(), block.getCreatedBy(), block.getLiftedBy());
    }

    static String formatRemaining(Duration duration) {
        long totalSeconds = Math.max(0, duration.toSeconds());
        if (totalSeconds >= 3600) {
            return String.format("%d h %02d min", totalSeconds / 3600, (totalSeconds % 3600) / 60);
        }
        return String.format("%d min %02d s", totalSeconds / 60, totalSeconds % 60);
    }

    private static String cut(String reason) {
        return reason.length() > 255 ? reason.substring(0, 255) : reason;
    }

    private LocalDateTime now() {
        return LocalDateTime.now(clock);
    }
}

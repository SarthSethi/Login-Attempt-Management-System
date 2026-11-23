package com.example.loginmonitoring.service;

import java.time.Clock;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.loginmonitoring.config.DateDisplay;
import com.example.loginmonitoring.dto.KeyCount;
import com.example.loginmonitoring.dto.TimeOutcome;
import com.example.loginmonitoring.entity.IpInfo;
import com.example.loginmonitoring.entity.LoginOutcome;
import com.example.loginmonitoring.repository.LoginAttemptRepository;
import com.example.loginmonitoring.service.intel.IpIntelService;

/**
 * Numbers and chart data for the admin overview. Charts are drawn as plain SVG on the server
 * (no JavaScript chart library), so the page also works with JavaScript switched off.
 */
@Service
public class StatsService {

    /** Size of the SVG drawing area (it scales to the page width). */
    static final int CHART_WIDTH = 720;
    static final int CHART_HEIGHT = 170;
    private static final int LEFT = 34;
    private static final int TOP = 8;
    private static final int BOTTOM = 22;

    public record Bar(String label, boolean showLabel, long success, long failed, long blocked,
                      String x, String width, String labelX,
                      String ySuccess, String hSuccess, String yFailed, String hFailed,
                      String yBlocked, String hBlocked, String tooltip) {
    }

    public record GridLine(String y, String labelY, long value) {
    }

    public record Chart(List<Bar> bars, List<GridLine> grid, long total, String period) {
        public int width() {
            return CHART_WIDTH;
        }

        public int height() {
            return CHART_HEIGHT;
        }

        public int baseline() {
            return CHART_HEIGHT - BOTTOM;
        }

        public int left() {
            return LEFT;
        }
    }

    public record IpRow(String ip, long count, int percent, IpInfo info) {
    }

    public record EmailRow(String email, long count, int percent) {
    }

    public record CountryRow(String flag, String name, long count, int percent) {
    }

    private final LoginAttemptRepository repository;
    private final IpIntelService ipIntelService;
    private final Clock clock;
    private final ZoneId zone;

    public StatsService(LoginAttemptRepository repository, IpIntelService ipIntelService, Clock clock,
                        DateDisplay dateDisplay) {
        this.repository = repository;
        this.ipIntelService = ipIntelService;
        this.clock = clock;
        this.zone = ZoneId.of(dateDisplay.zoneName());
    }

    @Transactional(readOnly = true)
    public long countSince(Duration period) {
        return repository.countByAttemptedAtAfter(now().minus(period));
    }

    @Transactional(readOnly = true)
    public long countSince(LoginOutcome outcome, Duration period) {
        return repository.countByOutcomeAndAttemptedAtAfter(outcome, now().minus(period));
    }

    /** Stacked bar chart: one bar per hour (last 24 h) or per day (last 7 days). */
    @Transactional(readOnly = true)
    public Chart activityChart(boolean week) {
        int buckets = week ? 7 : 24;
        ChronoUnit unit = week ? ChronoUnit.DAYS : ChronoUnit.HOURS;
        DateTimeFormatter format = DateTimeFormatter.ofPattern(week ? "EEE dd" : "HH:00", Locale.ENGLISH);

        // Buckets are aligned to the display time zone (e.g. midnight in India)
        LocalDateTime nowLocal = now().atOffset(ZoneOffset.UTC).atZoneSameInstant(zone).toLocalDateTime();
        LocalDateTime firstLocal = nowLocal.truncatedTo(unit).minus(buckets - 1L, unit);
        LocalDateTime firstUtc = firstLocal.atZone(zone).withZoneSameInstant(ZoneOffset.UTC).toLocalDateTime();

        long[][] counts = new long[buckets][3];
        for (TimeOutcome row : repository.timeline(firstUtc, Limit.of(200_000))) {
            LocalDateTime local = row.attemptedAt().atOffset(ZoneOffset.UTC).atZoneSameInstant(zone).toLocalDateTime();
            int index = (int) unit.between(firstLocal, local);
            if (index < 0 || index >= buckets) {
                continue;
            }
            counts[index][row.outcome().ordinal()]++;
        }

        long max = 1;
        long total = 0;
        for (long[] c : counts) {
            max = Math.max(max, c[0] + c[1] + c[2]);
            total += c[0] + c[1] + c[2];
        }
        long scaleMax = niceCeiling(max);
        double plotHeight = CHART_HEIGHT - TOP - BOTTOM;
        double slot = (CHART_WIDTH - LEFT) / (double) buckets;
        double barWidth = slot * 0.72;
        double baseline = CHART_HEIGHT - BOTTOM;

        List<Bar> bars = new ArrayList<>();
        for (int i = 0; i < buckets; i++) {
            long success = counts[i][LoginOutcome.SUCCESS.ordinal()];
            long failed = counts[i][LoginOutcome.FAILED.ordinal()];
            long blocked = counts[i][LoginOutcome.BLOCKED.ordinal()];
            double hS = success * plotHeight / scaleMax;
            double hF = failed * plotHeight / scaleMax;
            double hB = blocked * plotHeight / scaleMax;
            double x = LEFT + i * slot + (slot - barWidth) / 2;
            String label = firstLocal.plus(i, unit).format(format);
            boolean showLabel = week || i % 3 == 0;
            String tooltip = label + " - " + success + " successful, " + failed + " failed, " + blocked + " blocked";
            bars.add(new Bar(label, showLabel, success, failed, blocked, f(x), f(barWidth), f(x + barWidth / 2),
                    f(baseline - hS), f(hS),
                    f(baseline - hS - hF), f(hF),
                    f(baseline - hS - hF - hB), f(hB), tooltip));
        }

        List<GridLine> grid = new ArrayList<>();
        for (int step = 0; step <= 4; step++) {
            long value = scaleMax * step / 4;
            double y = baseline - plotHeight * step / 4;
            grid.add(new GridLine(f(y), f(y + 4), value));
        }
        return new Chart(bars, grid, total, week ? "last 7 days" : "last 24 hours");
    }

    @Transactional(readOnly = true)
    public List<IpRow> topAttackingIps(Duration period, int max) {
        List<KeyCount> rows = repository.topUnsuccessfulIps(now().minus(period), Limit.of(max));
        Map<String, IpInfo> info = ipIntelService.describeAll(rows.stream().map(KeyCount::key).toList());
        long top = rows.isEmpty() ? 1 : rows.get(0).count();
        return rows.stream().map(r -> new IpRow(r.key(), r.count(), percent(r.count(), top), info.get(r.key()))).toList();
    }

    @Transactional(readOnly = true)
    public List<EmailRow> topTargetedAccounts(Duration period, int max) {
        List<KeyCount> rows = repository.topTargetedEmails(now().minus(period), Limit.of(max));
        long top = rows.isEmpty() ? 1 : rows.get(0).count();
        return rows.stream().map(r -> new EmailRow(r.key(), r.count(), percent(r.count(), top))).toList();
    }

    /** Attempts grouped by the country of the IP. */
    @Transactional(readOnly = true)
    public List<CountryRow> countries(Duration period, int max) {
        List<KeyCount> perIp = repository.attemptsPerIp(now().minus(period));
        Map<String, IpInfo> info = ipIntelService.describeAll(perIp.stream().map(KeyCount::key).toList());
        Map<String, long[]> byCountry = new HashMap<>();
        Map<String, String> flags = new HashMap<>();
        for (KeyCount row : perIp) {
            IpInfo ipInfo = info.get(row.key());
            String name = ipInfo.getCountry() != null ? ipInfo.getCountry() : ipInfo.getLocationLabel();
            byCountry.computeIfAbsent(name, k -> new long[1])[0] += row.count();
            flags.putIfAbsent(name, ipInfo.getFlag());
        }
        List<Map.Entry<String, long[]>> sorted = new ArrayList<>(byCountry.entrySet());
        sorted.sort((a, b) -> Long.compare(b.getValue()[0], a.getValue()[0]));
        long top = sorted.isEmpty() ? 1 : sorted.get(0).getValue()[0];
        return sorted.stream().limit(max)
                .map(e -> new CountryRow(flags.get(e.getKey()), e.getKey(), e.getValue()[0], percent(e.getValue()[0], top)))
                .toList();
    }

    private static int percent(long value, long top) {
        return (int) Math.max(2, Math.round(value * 100.0 / Math.max(1, top)));
    }

    /** 1, 2, 5, 10, 20, 50, ... so the axis has round numbers. */
    static long niceCeiling(long value) {
        long magnitude = 1;
        while (magnitude * 10 < value) {
            magnitude *= 10;
        }
        for (long factor : new long[] {1, 2, 4, 5, 10}) {
            if (magnitude * factor >= value) {
                return Math.max(4, magnitude * factor);
            }
        }
        return Math.max(4, magnitude * 10);
    }

    private static String f(double value) {
        return String.format(Locale.ROOT, "%.1f", value);
    }

    private LocalDateTime now() {
        return LocalDateTime.now(clock);
    }
}

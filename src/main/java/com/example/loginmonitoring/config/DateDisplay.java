package com.example.loginmonitoring.config;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Formats the UTC timestamps from the database in the display time zone
 * (app.display-timezone). Used from the templates as {@code ${@dates.format(...)}}.
 */
@Component("dates")
public class DateDisplay {

    private static final DateTimeFormatter FORMAT = DateTimeFormatter.ofPattern("dd MMM yyyy, HH:mm:ss", Locale.ENGLISH);

    private final ZoneId zone;

    public DateDisplay(@Value("${app.display-timezone:UTC}") String displayTimeZone) {
        this.zone = ZoneId.of(displayTimeZone);
    }

    public String format(LocalDateTime utcDateTime) {
        if (utcDateTime == null) {
            return "-";
        }
        return utcDateTime.atOffset(ZoneOffset.UTC).atZoneSameInstant(zone).format(FORMAT);
    }

    public String zoneName() {
        return zone.getId();
    }
}

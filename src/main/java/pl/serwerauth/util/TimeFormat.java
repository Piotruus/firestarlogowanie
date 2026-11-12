package pl.serwerauth.util;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public final class TimeFormat {

    private static final DateTimeFormatter DATE =
            DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm:ss").withZone(ZoneId.systemDefault());

    private TimeFormat() {
    }

    /** Np. 45 s, 2 min 5 s, 1 h 3 min. */
    public static String format(long ms) {
        long s = (ms + 999) / 1000;
        if (s < 60) return s + " s";
        long m = s / 60;
        long r = s % 60;
        if (m < 60) return m + " min" + (r > 0 ? " " + r + " s" : "");
        return (m / 60) + " h " + (m % 60) + " min";
    }

    public static String date(long epochMs) {
        return epochMs <= 0 ? "—" : DATE.format(Instant.ofEpochMilli(epochMs));
    }
}

package dev.rexijie.oauth.oauth2server.util;

import java.util.Date;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;

public class TimeUtils {
    public static final String TIME_ZONE = "GMT+1";

    public static LocalDateTime localDateTimeFromEpochSecond(long epochSecond) {
        return LocalDateTime.ofInstant(Instant.ofEpochSecond(epochSecond), ZoneId.of(TIME_ZONE));
    }

    public static long localDateTimeToEpochSecond(LocalDateTime localDateTime) {
        return localDateTime.toInstant(ZoneOffset.UTC).getEpochSecond();
    }

    public static Date secondsFromNow(int seconds) {
        return fromNow(seconds, ChronoUnit.SECONDS);
    }
    public static Date minutesFromNow(int minutes) {
        return fromNow(minutes, ChronoUnit.MINUTES);
    }

    private static Date fromNow(int time, ChronoUnit unit) {
        return Date.from(Instant.now().plus(time, unit));
    }
}

package dev.rexijie.oauth.oauth2server.util;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;

public class TimeUtils {
    public static final String TIME_ZONE = "GMT+1";

    public static LocalDateTime localDateTimeFromEpochSecond(long epochSecond) {
        return LocalDateTime.ofInstant(Instant.ofEpochSecond(epochSecond), ZoneId.of(TIME_ZONE));
    }

    public static long localDateTimeToEpochSecond(LocalDateTime localDateTime) {
        return localDateTime.toInstant(ZoneOffset.UTC).getEpochSecond();
    }
}

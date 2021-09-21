package dev.rexijie.oauth.oauth2server.model;

import java.time.LocalDateTime;

import static dev.rexijie.oauth.oauth2server.util.TimeUtils.localDateTimeFromEpochSecond;
import static dev.rexijie.oauth.oauth2server.util.TimeUtils.localDateTimeToEpochSecond;


public class Entity {
    private String id;
    private long createdAt;
    private long updatedAt;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public LocalDateTime getCreatedAt() {
        return localDateTimeFromEpochSecond(createdAt);
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = localDateTimeToEpochSecond(createdAt);
    }

    public LocalDateTime getUpdatedAt() {
        return localDateTimeFromEpochSecond(updatedAt);
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = localDateTimeToEpochSecond(updatedAt);
    }
}

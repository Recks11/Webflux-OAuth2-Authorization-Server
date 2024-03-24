package dev.rexijie.oauth.oauth2server.auth;

public enum AuthenticationStage {
    STARTED("STARTED"),
    PENDING_APPROVAL("NEEDS APPROVAL"),
    COMPLETE("AUTHENTICATED");

    private final String stage;

    AuthenticationStage(String stage) {
        this.stage = stage;
    }

    @Override
    public String toString() {
        return stage;
    }
}

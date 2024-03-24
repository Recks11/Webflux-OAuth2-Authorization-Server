package dev.rexijie.oauth.oauth2server.token;

public enum TokenType {
    JWT("jwt"),
    BASIC("basic");

    private final String type;

    TokenType(String type) {
        this.type = type;
    }

    public String getType() {
        return type;
    }

    @Override
    public String toString() {
        return type+" token";
    }
}

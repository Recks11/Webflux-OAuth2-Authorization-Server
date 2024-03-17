package dev.rexijie.oauth.oauth2server.model;

public enum ClientTypes {
    CONFIDENTIAL("confidential", "Client that can maintain the confidentiality of their client secret"),
    PUBLIC("public", "Client that can not maintain the confidentiality of their client secret");

    private final String name;
    private final String description;
    ClientTypes(String name, String description) {
        this.name = name;
        this.description = description;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public String toString() {
        return getName();
    }
}

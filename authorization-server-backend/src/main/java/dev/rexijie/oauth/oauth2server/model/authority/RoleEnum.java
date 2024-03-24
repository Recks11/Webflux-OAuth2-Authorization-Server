package dev.rexijie.oauth.oauth2server.model.authority;

public enum RoleEnum {
    USER("USER", "Standard application user"),
    ADMIN("ADMIN", "System administrator");

    private final String name;
    private final String description;

    RoleEnum(String name, String description) {
        this.name = name;
        this.description = description;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }
}

package dev.rexijie.oauth.oauth2server.model.authority;

public enum AuthorityEnum {
    CAN_CREATE("CAN_CREATE", "has authority to create"),
    CAN_MODIFY("CAN_CREATE", "has authority to modify"),
    CAN_VIEW("CAN_VIEW", "has authority to view"),
    CAN_DELETE("CAN_DELETE", "has authority to delete"),
    CLIENT("CLIENT", "application only authority. can request for tokens on behalf of users");

    private final String name;
    private final String description;

    AuthorityEnum(String name, String description) {
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

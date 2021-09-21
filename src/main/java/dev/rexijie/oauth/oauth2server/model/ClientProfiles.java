package dev.rexijie.oauth.oauth2server.model;

public enum ClientProfiles {
    WEB("web", "A confidential client running on a server"),
    USER_AGENT_APPLICATION("user-agent-web-application", "A public client running on a browser or a user-agent"),
    NATIVE("native", "A public client installed and executed on a device");

    private final String name;
    private final String description;
    ClientProfiles(String name, String description) {
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

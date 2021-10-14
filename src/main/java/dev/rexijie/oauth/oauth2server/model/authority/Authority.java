package dev.rexijie.oauth.oauth2server.model.authority;
import org.springframework.security.core.GrantedAuthority;

import java.util.UUID;

public class Authority implements GrantedAuthority {
    private String id;
    private String name;
    private String description;

    public Authority() {
    }

    public Authority(String name) {
        this.id = UUID.randomUUID().toString();
        this.name = name;
        this.description = "";
    }

    public Authority(String name, String description) {
        this.id = UUID.randomUUID().toString();
        this.name = name;
        this.description = description;
    }

    public Authority(AuthorityEnum authorityEnum) {
        this(authorityEnum.getName(), authorityEnum.getDescription());
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    @Override
    public String getAuthority() {
        return "ROLE_" + name;
    }

    @Override
    public String toString() {
        return getAuthority();
    }
}

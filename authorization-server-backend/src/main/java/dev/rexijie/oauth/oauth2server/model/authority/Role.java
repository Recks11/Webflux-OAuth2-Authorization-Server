package dev.rexijie.oauth.oauth2server.model.authority;

import dev.rexijie.oauth.oauth2server.model.Entity;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

public class Role extends Entity implements Serializable {
    @Serial
    private static final long serialVersionUID = 1373828140005067324L;
    private final String name;
    private final String description;
    private Set<Authority> authorities = new HashSet<>();

    public Role(RoleEnum roleEnum) {
        this.name = roleEnum.getName();
        this.description = roleEnum.getDescription();
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public Set<Authority> getAuthorities() {
        return authorities;
    }

    public void setAuthorities(Set<Authority> authorities) {
        this.authorities = authorities;
    }

    public Role(RoleEnum roleEnum, Collection<Authority> authorities) {
        this(roleEnum);
        this.authorities = Set.copyOf(authorities);
    }
}

package dev.rexijie.oauth.oauth2server.model.dto;

import dev.rexijie.oauth.oauth2server.model.authority.Authority;

public class AuthorityDto {
    private final String name;

    public AuthorityDto(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public static class Mapper {
        public static AuthorityDto toDto(Authority authority) {
            return new AuthorityDto(authority.getName());
        }
    }
}

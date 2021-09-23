package dev.rexijie.oauth.oauth2server.model;

import dev.rexijie.oauth.oauth2server.model.authority.Authority;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public record ClientUserDetails(String username,
                                String password,
                                List<Authority> authorities,
                                Client clientData) implements UserDetails {
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities();
    }

    @Override
    public String getPassword() {
        return password();
    }

    @Override
    public String getUsername() {
        return username();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    public ClientUserDetails(Client clientData) {
        this(clientData.clientId(),
                clientData.clientSecret(),
                clientData.authorities().stream().map(Authority::new).collect(Collectors.toList()),
                clientData);
    }
}

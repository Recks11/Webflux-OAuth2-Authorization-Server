package dev.rexijie.oauth.oauth2server.converter;

import dev.rexijie.oauth.oauth2server.model.Client;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

public class ClientConverter {

    public static UserDetails clientToUserDetails(Client client) {
        return User.builder()
                .passwordEncoder(s -> s)
                .username(client.clientId())
                .password(client.clientSecret())
                .credentialsExpired(false)
                .authorities(client.authorities().toArray(new String[]{}))
                .roles(client.authorities().toArray(new String[]{}))
                .build();
    }
}

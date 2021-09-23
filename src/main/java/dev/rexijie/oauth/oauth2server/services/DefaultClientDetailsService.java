package dev.rexijie.oauth.oauth2server.services;

import dev.rexijie.oauth.oauth2server.api.domain.ClientCredentials;
import dev.rexijie.oauth.oauth2server.model.ClientUserDetails;
import dev.rexijie.oauth.oauth2server.model.dto.ClientDTO;
import dev.rexijie.oauth.oauth2server.repository.ClientRepository;
import org.springframework.security.core.userdetails.ReactiveUserDetailsPasswordService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class DefaultClientDetailsService implements ReactiveUserDetailsService, ReactiveUserDetailsPasswordService {

    private final ClientRepository clientRepository;
    private final PasswordEncoder encoder;

    public DefaultClientDetailsService(ClientRepository clientRepository,
                                       PasswordEncoder encoder) {
        this.clientRepository = clientRepository;
        this.encoder = encoder;
    }

    @Override
    public Mono<UserDetails> findByUsername(String username) {
        return clientRepository.findByClientId(username)
                .map(ClientUserDetails::new);
    }

    @Override
    public Mono<UserDetails> updatePassword(UserDetails user, String newPassword) {
        return clientRepository.findByClientId(user.getUsername())
                .map(client -> ClientDTO.ClientMapper.withCredentials(client, new ClientCredentials(
                        client.id(),
                        encoder.encode(newPassword)))
                ).map(ClientUserDetails::new);
    }

}
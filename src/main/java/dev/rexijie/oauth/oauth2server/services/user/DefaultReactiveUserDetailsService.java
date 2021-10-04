package dev.rexijie.oauth.oauth2server.services.user;

import dev.rexijie.oauth.oauth2server.repository.UserRepository;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import reactor.core.publisher.Mono;

public class DefaultReactiveUserDetailsService implements ReactiveUserDetailsService {

    private final UserRepository userRepository;

    public DefaultReactiveUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public Mono<UserDetails> findByUsername(String username) {
        return userRepository.findByUsername(username)
                .map(UserDetails.class::cast);
    }
}

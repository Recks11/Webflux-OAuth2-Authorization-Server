package dev.rexijie.oauth.oauth2server.repository;

import dev.rexijie.oauth.oauth2server.model.User;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;

import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import reactor.core.publisher.Mono;

public interface UserRepository extends ReactiveMongoRepository<User, String> {
    Mono<User> findByUsername(String username);
}

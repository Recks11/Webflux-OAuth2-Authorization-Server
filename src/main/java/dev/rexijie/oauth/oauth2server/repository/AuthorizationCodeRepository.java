package dev.rexijie.oauth.oauth2server.repository;

import dev.rexijie.oauth.oauth2server.auth.AuthenticationSerializationWrapper;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import reactor.core.publisher.Mono;

public interface AuthorizationCodeRepository extends ReactiveMongoRepository<AuthenticationSerializationWrapper, String> {
    Mono<AuthenticationSerializationWrapper> findByCode(String code);
    Mono<Void> deleteByCode(String code);
}

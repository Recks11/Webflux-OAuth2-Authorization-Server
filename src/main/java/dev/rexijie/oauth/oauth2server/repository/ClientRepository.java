package dev.rexijie.oauth.oauth2server.repository;

import dev.rexijie.oauth.oauth2server.model.Client;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import reactor.core.publisher.Mono;

public interface ClientRepository extends ReactiveMongoRepository<Client, String> {
    Mono<Client> findByClientId(String clientId);
    Mono<Client> findByClientIdAndClientSecret(String clientId, String clientSecret);
    Mono<Void> deleteClientByClientId(String clientId);
}

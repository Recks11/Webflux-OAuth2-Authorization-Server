package dev.rexijie.oauth.oauth2server.services;

import dev.rexijie.oauth.oauth2server.api.domain.ClientCredentials;
import dev.rexijie.oauth.oauth2server.model.dto.ClientDTO;
import reactor.core.publisher.Mono;

public interface ClientService {
    Mono<ClientCredentials> createClient(ClientDTO clientDTO);
    Mono<ClientDTO> findClientById(String credentials);
    Mono<ClientDTO> findClientWithCredentials(ClientCredentials credentials);
}

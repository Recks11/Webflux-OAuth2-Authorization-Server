package dev.rexijie.oauth.oauth2server.api.handlers;

import dev.rexijie.oauth.oauth2server.model.dto.ClientDTO;
import dev.rexijie.oauth.oauth2server.services.ClientService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.CacheControl;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

@Component
public class ClientEndpointHandler extends ApiEndpointHandler {
    private static final Logger LOG = LoggerFactory.getLogger(ClientEndpointHandler.class);
    private final ClientService clientService;

    public ClientEndpointHandler(ClientService clientService) {
        this.clientService = clientService;
    }

    public Mono<ServerResponse> createClient(ServerRequest request) {
        return request.bodyToMono(ClientDTO.class)
                .flatMap(clientService::createClient)
                .flatMap(credentials -> ServerResponse
                        .ok()
                        .cacheControl(CacheControl.noCache())
                        .bodyValue(credentials));
    }
}

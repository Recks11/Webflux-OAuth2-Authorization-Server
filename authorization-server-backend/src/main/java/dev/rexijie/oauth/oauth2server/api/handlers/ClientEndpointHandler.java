package dev.rexijie.oauth.oauth2server.api.handlers;

import dev.rexijie.oauth.oauth2server.model.dto.ClientDTO;
import dev.rexijie.oauth.oauth2server.services.client.ClientService;
import dev.rexijie.oauth.oauth2server.validation.ClientValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.CacheControl;
import org.springframework.stereotype.Component;
import org.springframework.validation.Validator;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

@Component
public class ClientEndpointHandler extends ApiEndpointHandler implements Handler<ClientDTO> {
    private static final Logger LOG = LoggerFactory.getLogger(ClientEndpointHandler.class);
    private final ClientService clientService;

    public ClientEndpointHandler(ClientService clientService) {
        this.clientService = clientService;
    }

    public Mono<ServerResponse> createClient(ServerRequest request) {
        return extractAndValidateDto(request)
                .flatMap(clientService::createClient)
                .flatMap(credentials -> ServerResponse
                        .ok()
                        .cacheControl(CacheControl.noCache())
                        .bodyValue(credentials));
    }

    @Override
    public Class<ClientDTO> getInnerClass() {
        return ClientDTO.class;
    }

    @Override
    public String getValidationKey() {
        return "client";
    }

    @Override
    public Validator getValidator() {
        return new ClientValidator();
    }
}

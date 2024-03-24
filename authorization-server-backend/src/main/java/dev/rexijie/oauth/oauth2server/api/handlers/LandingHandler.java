package dev.rexijie.oauth.oauth2server.api.handlers;

import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

@Component
public class LandingHandler extends ApiEndpointHandler {
    public Mono<ServerResponse> homePage(ServerRequest request) {
        return ServerResponse.
                ok()
                .build();
    }
}

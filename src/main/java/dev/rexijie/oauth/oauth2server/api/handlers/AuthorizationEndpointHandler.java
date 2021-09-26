package dev.rexijie.oauth.oauth2server.api.handlers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

@Component
public class AuthorizationEndpointHandler extends OAuthEndpointHandler {
    private static final Logger LOG = LoggerFactory.getLogger(AuthorizationEndpointHandler.class);

    public Mono<ServerResponse> authorizeRequest(ServerRequest request) {
        return extractAuthorizationRequest(request)
                .flatMap(authorizationRequest -> ServerResponse.ok().build())
                .onErrorResume(err -> redirectToLogin());
    }

    public Mono<ServerResponse> initiateAuthorization(ServerRequest serverRequest) {
        return serverRequest.session()
                .flatMap(session -> ServerResponse
                        .ok().
                        bodyValue(session));
    }
}

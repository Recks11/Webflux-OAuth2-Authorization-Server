package dev.rexijie.oauth.oauth2server.api.handlers;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

import java.net.URI;

public abstract class OAuthEndpointHandler {
    private static final Logger LOG = LoggerFactory.getLogger(OAuthEndpointHandler.class);

    protected Mono<AuthorizationRequest> extractAuthorizationRequest(ServerRequest request) {
        return request.formData()
                .switchIfEmpty(Mono.just(request.queryParams()))
                .map(MultiValueMap::toSingleValueMap)
                .map(AuthorizationRequest::from)
                .doOnNext(authorizationRequest -> LOG.info("converted to authorization request: {}", authorizationRequest))
                .doOnError(throwable -> {throw Exceptions.propagate(throwable);});
    }

    protected Mono<ServerResponse> redirectToLogin() {
        return ServerResponse
                .temporaryRedirect(URI.create("/login"))
//                .cookie(ResponseCookie.from().build())
                .build();
    }
}

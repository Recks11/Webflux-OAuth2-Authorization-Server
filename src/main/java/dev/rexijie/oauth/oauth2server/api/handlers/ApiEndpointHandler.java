package dev.rexijie.oauth.oauth2server.api.handlers;

import dev.rexijie.oauth.oauth2server.error.OAuthError;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

public abstract class ApiEndpointHandler {

    public Mono<ServerResponse> forbiddenResponse(ServerRequest serverRequest) {
        return ServerResponse.status(HttpStatus.FORBIDDEN).build();
    }


    <T> Mono<T> bodyToMono(ServerRequest request, Class<T> tClass) {
        return request.bodyToMono(tClass)
                .doOnError(throwable -> {throw Exceptions.propagate(new OAuthError(OAuthError.OAuthErrors.INVALID_REQUEST, throwable));});
    }
}

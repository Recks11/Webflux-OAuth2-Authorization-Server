package dev.rexijie.oauth.oauth2server.api.handlers;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyExtractors;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.util.DefaultUriBuilderFactory;
import org.springframework.web.util.UriBuilderFactory;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Map;

public abstract class OAuthEndpointHandler {
    private static final Logger LOG = LoggerFactory.getLogger(OAuthEndpointHandler.class);

    protected Mono<AuthorizationRequest> extractAuthorizationFromParams(ServerRequest request) {
        return Mono.just(request.queryParams())
                .map(MultiValueMap::toSingleValueMap)
                .map(AuthorizationRequest::from)
                .doOnNext(authorizationRequest -> LOG.info("converted to query from authorization request 1: {}", authorizationRequest))
                .doOnError(throwable -> {throw Exceptions.propagate(throwable);});
    }

    protected Mono<AuthorizationRequest> extractAuthorizationFromBody(ServerRequest request) {
        return request.formData().flatMap(formMap -> {
            if (formMap.isEmpty()) return request.body(BodyExtractors.toMono(new ParameterizedTypeReference<Map<String, String>>(){}));
            return Mono.just(formMap.toSingleValueMap());
        })
                .map(AuthorizationRequest::from)
                .doOnNext(authorizationRequest -> LOG.info("converted to query from authorization request 2: {}", authorizationRequest))
                .doOnError(throwable -> {throw Exceptions.propagate(throwable);});
    }

    protected Mono<ServerResponse> redirectTo(ServerRequest request, String path) {
        var params = request.queryParams();
        if (params.isEmpty()) return ServerResponse
                .temporaryRedirect(URI.create(path))
                .build();
        URI build = new DefaultUriBuilderFactory()
                .builder()
                .path(path)
                .queryParams(params).build();
        return ServerResponse
                .temporaryRedirect(build)
                .build();
    }
}

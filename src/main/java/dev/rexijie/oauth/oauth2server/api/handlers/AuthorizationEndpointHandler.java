package dev.rexijie.oauth.oauth2server.api.handlers;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;

@Component
public class AuthorizationEndpointHandler extends OAuthEndpointHandler {
    private static final Logger LOG = LoggerFactory.getLogger(AuthorizationEndpointHandler.class);



    // path GET /oauth/authorize
    public Mono<ServerResponse> initiateAuthorization(ServerRequest serverRequest) {
        return serverRequest.session()
                .doOnNext(WebSession::start)
                .doOnNext(session -> LOG.info("session: {}", session.toString()))
                .flatMap(session -> redirectToLogin());
    }

    // path POST /oauth/authorize
    public Mono<ServerResponse> authorizeRequest(ServerRequest request) {
        return extractAuthorizationFromParams(request)
                .flatMap(this::authorize)
                .onErrorResume(err -> redirectToLogin());
    }

    private Mono<ServerResponse> authorize(AuthorizationRequest request) {
        String grantType = request.getGrantType();
        if (!grantType.equals("code")) return ServerResponse.badRequest().build();

        return Mono.empty();
    }

    // Algorithm:
    // 1. get authorization request
    // 2. redirect to login page with session id
    // 3. receive credentials and authenticate
    // 4. on login, redirect to approve page
    // 5. after approve, redirect to response with credentials
}

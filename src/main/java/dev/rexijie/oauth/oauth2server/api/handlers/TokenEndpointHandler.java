package dev.rexijie.oauth.oauth2server.api.handlers;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.api.domain.OAuth2TokenResponse;
import dev.rexijie.oauth.oauth2server.token.granter.TokenGranter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.CacheControl;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Component
public class TokenEndpointHandler extends ApiEndpointHandler {
    private static final Logger LOG = LoggerFactory.getLogger(TokenEndpointHandler.class);
    private final ReactiveAuthenticationManager authenticationManager;
    private final TokenGranter tokenGranter;

    public TokenEndpointHandler(
            @Qualifier("userAuthenticationManager") ReactiveAuthenticationManager authenticationManager,
            TokenGranter tokenGranter) {
        this.authenticationManager = authenticationManager;
        this.tokenGranter = tokenGranter;
    }

    //    private final

    public Mono<ServerResponse> getToken(ServerRequest request) {
        return extractAuthorizationRequest(request)
                .doOnNext(authorizationRequest -> LOG.info("found request: {}", authorizationRequest))
                .flatMap(authorizationRequest -> request.principal()
                        .flatMap(principal -> tokenGranter.grantToken((Authentication) principal, authorizationRequest)))
                .cast(OAuth2AccessToken.class)
                .flatMap(token -> ServerResponse
                        .ok()
                        .cacheControl(CacheControl.noCache())
                        .bodyValue(OAuth2TokenResponse.fromAccessToken(token)
                        ));

    }


    public Mono<ServerResponse> getTokenKey(ServerRequest request) {
        Optional<Object> attribute = request.attribute(CsrfToken.class.getName());
        if (attribute.isEmpty()) return ServerResponse.ok().bodyValue("empty attr");

        return ((Mono<CsrfToken>) attribute.get())
                .flatMap(csrfToken -> ServerResponse
                        .ok()
                        .header(csrfToken.getHeaderName(), csrfToken.getToken())
                        .bodyValue(csrfToken));
    }

    private Mono<AuthorizationRequest> extractAuthorizationRequest(ServerRequest request) {
        return request.formData()
                .switchIfEmpty(Mono.just(request.queryParams()))
                .map(MultiValueMap::toSingleValueMap)
                .map(AuthorizationRequest::from);
    }

    private String handle(ServerRequest request) {
        Map<String, String> paramMap = new HashMap<>(request.queryParams().toSingleValueMap());

        AuthorizationRequest authenticationRequest = AuthorizationRequest.from(paramMap);
        handleAuthenticationRequest(authenticationRequest)
                .doOnNext(System.out::println)
                .doOnError(System.err::println)
                .subscribe();
        return authenticationRequest.getGrantType();
    }

    private Mono<Authentication> handleAuthenticationRequest(AuthorizationRequest request) {
        return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                "rexijie", "password"
        ));
    }
}

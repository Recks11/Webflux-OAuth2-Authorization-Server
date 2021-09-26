package dev.rexijie.oauth.oauth2server.api.handlers;

import com.nimbusds.jose.jwk.JWKSet;
import dev.rexijie.oauth.oauth2server.api.domain.OAuth2TokenResponse;
import dev.rexijie.oauth.oauth2server.token.granter.TokenGranter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.CacheControl;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

@Component
public class TokenEndpointHandler extends OAuthEndpointHandler {
    private static final Logger LOG = LoggerFactory.getLogger(TokenEndpointHandler.class);
    private final ReactiveAuthenticationManager authenticationManager;
    private final TokenGranter tokenGranter;
    private final JWKSet jwkSet;

    public TokenEndpointHandler(
            @Qualifier("userAuthenticationManager") ReactiveAuthenticationManager authenticationManager,
            TokenGranter tokenGranter,
            JWKSet jwkSet) {
        this.authenticationManager = authenticationManager;
        this.tokenGranter = tokenGranter;
        this.jwkSet = jwkSet;
    }

    public Mono<ServerResponse> getToken(ServerRequest request) {
        return extractAuthorizationRequest(request) // extract authentication request
                .flatMap(authorizationRequest -> request.principal() // get authenticated client credentials from request
                        .flatMap(principal -> tokenGranter.grantToken((Authentication) principal, authorizationRequest) // grant token
                                .cast(OAuth2AccessToken.class)) // cast to OAuth2AccessToken class
                        .map(OAuth2TokenResponse::fromAccessToken)) // convert to access token response
                .flatMap(token -> ServerResponse
                        .ok()
                        .cacheControl(CacheControl.noCache())
                        .bodyValue(token));

    }

    public Mono<ServerResponse> getTokenKey(ServerRequest request) {
        return ServerResponse.ok()
                .cacheControl(CacheControl.noCache())
                .bodyValue(jwkSet.toJSONObject());
    }

}

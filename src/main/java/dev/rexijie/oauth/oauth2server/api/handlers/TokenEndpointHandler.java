package dev.rexijie.oauth.oauth2server.api.handlers;

import com.nimbusds.jose.jwk.JWKSet;
import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.api.domain.OAuth2TokenResponse;
import dev.rexijie.oauth.oauth2server.token.granter.TokenGranter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.CacheControl;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

@Component
public class TokenEndpointHandler extends OAuthEndpointHandler {
    private static final Logger LOG = LoggerFactory.getLogger(TokenEndpointHandler.class);
    private final TokenGranter tokenGranter;
    private final JWKSet jwkSet;

    public TokenEndpointHandler(
            TokenGranter tokenGranter,
            JWKSet jwkSet) {
        this.tokenGranter = tokenGranter;
        this.jwkSet = jwkSet;
    }

    // TODO (if an authorization code is used more than once, then revoke all tokens issued with that code)

    public Mono<ServerResponse> getToken(ServerRequest request) {
        return extractAuthorization(request)
                .doOnNext(authorizationRequest -> LOG.debug("Granting token for request {}", request.uri()))
                .flatMap(authorizationRequest -> request.principal() // get authenticated client credentials from request
                        .flatMap(principal -> tokenGranter.grantToken((Authentication) principal, authorizationRequest) // grant token
                                .cast(OAuth2AccessToken.class))// cast to OAuth2AccessToken class
                        .map(OAuth2TokenResponse::fromAccessToken)) // convert to access token response
                .doOnNext(oAuth2TokenResponse -> LOG.debug("Successfully Granted Token"))
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

    private Mono<AuthorizationRequest> extractAuthorization(ServerRequest request) {
        return extractAuthorizationFromBody(request) // extract userAuthentication request
                .switchIfEmpty(extractAuthorizationFromParams(request));
    }
}

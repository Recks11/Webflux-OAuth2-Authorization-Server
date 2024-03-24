package dev.rexijie.oauth.oauth2server.auth.converter;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.api.domain.OAuth2AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.token.OAuth2Authentication;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerHttpBasicAuthenticationConverter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static dev.rexijie.oauth.oauth2server.util.AuthenticationUtils.extractAuthenticationFromExchange;

public class HttpBasicAuthenticationConverter extends ServerHttpBasicAuthenticationConverter {

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        return extractAuthenticationFromExchange(exchange)
                .flatMap(params -> super.convert(exchange).map(authentication -> {
                    var auth = new OAuth2Authentication(authentication.getPrincipal(), authentication.getCredentials());
                    auth.setAuthorizationRequest(
                            new OAuth2AuthorizationRequest(
                                    AuthorizationRequest.from(params), null
                            )
                    );
                    return auth;
                }));
    }
}

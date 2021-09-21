package dev.rexijie.oauth.oauth2server.api.handlers;

import com.nimbusds.jose.jwk.JWKSet;
import dev.rexijie.oauth.oauth2server.config.OAuth2Properties;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

@Component
public class OpenIdConnectHandler extends ApiEndpointHandler {

    private final OAuth2Properties.OidcProperties properties;
    private final JWKSet jwkSet;

    public OpenIdConnectHandler(OAuth2Properties properties, JWKSet jwkSet) {
        this.properties = properties.openId();
        this.jwkSet = jwkSet;
    }

    public Mono<ServerResponse> getOpenIdProperties(ServerRequest request) {
        return ServerResponse
                .ok().bodyValue(properties);
    }

    public Mono<ServerResponse> getJwkSet(ServerRequest request) {
        return ServerResponse
                .ok()
                .bodyValue(jwkSet.toJSONObject());
    }
}

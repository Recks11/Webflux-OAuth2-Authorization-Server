package dev.rexijie.oauth.oauth2server.auth;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import dev.rexijie.oauth.oauth2server.auth.converter.ServerClientSecretPostAuthenticationConverter;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerHttpBasicAuthenticationConverter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * The Authentication converter is responsible for extracting the userAuthentication from requests (to the best of my understanding)
 * Authentication converter that returns a token other than the default UsernamePasswordAuthenticationToken
 * gotten from {@link org.springframework.security.web.server.authentication.ServerHttpBasicAuthenticationConverter}
 */

public class AuthenticationServerAuthenticationConverter implements ServerAuthenticationConverter {
    private final Map<ClientAuthenticationMethod, ServerAuthenticationConverter> converterMap;

    public AuthenticationServerAuthenticationConverter() {
        converterMap = Map.of(
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, new ServerHttpBasicAuthenticationConverter(),
                ClientAuthenticationMethod.CLIENT_SECRET_POST, new ServerClientSecretPostAuthenticationConverter()
        );
    }

    private final ReactiveClientAuthenticationMethodResolver clientAuthenticationMethodResolver =
            new DefaultClientAuthenticationMethodResolver();

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        return clientAuthenticationMethodResolver.resolveClientAuthenticationMethod(exchange)
                .map(clientAuthenticationMethod -> converterMap.getOrDefault(clientAuthenticationMethod, emptyAuth()))
                .flatMap(serverAuthenticationConverter -> serverAuthenticationConverter.convert(exchange));
    }

    private ServerAuthenticationConverter emptyAuth() {
        return (exchange) -> Mono.empty();
    }
}

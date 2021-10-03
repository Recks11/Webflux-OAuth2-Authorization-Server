package dev.rexijie.oauth.oauth2server.auth;

import dev.rexijie.oauth.oauth2server.model.Client;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerHttpBasicAuthenticationConverter;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * The Authentication converter is responsible for extracting the userAuthentication from requests (to the best of my understanding)
 * Authentication converter that returns a token other than the default UsernamePasswordAuthenticationToken
 * gotten from {@link org.springframework.security.web.server.authentication.ServerHttpBasicAuthenticationConverter}
 */

public class AuthenticationServerAuthenticationConverter implements ServerAuthenticationConverter {
    private final Map<ClientAuthenticationMethod, ServerAuthenticationConverter> converterMap = Map.of(
            ClientAuthenticationMethod.CLIENT_SECRET_BASIC, new ServerHttpBasicAuthenticationConverter()
    );

//    private final ReactiveClientAuthenticationMethodResolver clientAuthenticationMethodResolver =
//            new DefaultClientAuthenticationMethodResolver();

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
//        clientAuthenticationMethodResolver.resolveClientAuthenticationMethod(exchange)
//                .map(converterMap::get)
//                .flatMap(serverAuthenticationConverter -> serverAuthenticationConverter.convert(exchange));

        ServerHttpRequest request = exchange.getRequest();
        String authorization = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (StringUtils.startsWithIgnoreCase(authorization, "basic "))
            return handleBasicAuth(exchange);

        return Mono.empty();
    }

    private Mono<Authentication> handleBasicAuth(ServerWebExchange exchange) {
        return converterMap.get(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).convert(exchange);
    }
}

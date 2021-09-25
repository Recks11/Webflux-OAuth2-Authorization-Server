package dev.rexijie.oauth.oauth2server.auth;

import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerHttpBasicAuthenticationConverter;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Authentication converter that returns a token other than the default UsernamePasswordAuthenticationToken
 * gotten from {@link org.springframework.security.web.server.authentication.ServerHttpBasicAuthenticationConverter}
 *
 */

public class AuthenticationServerAuthenticationConverter implements ServerAuthenticationConverter {
    public static final String BASIC = "Basic ";

    private final ServerAuthenticationConverter basicAuthDelegate = new ServerHttpBasicAuthenticationConverter();

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        ServerHttpRequest request = exchange.getRequest();
        String authorization = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (StringUtils.startsWithIgnoreCase(authorization, "basic "))
            return handleBasicAuth(exchange);

        return Mono.empty();
    }

    private Mono<Authentication> handleBasicAuth(ServerWebExchange exchange) {
        return basicAuthDelegate.convert(exchange);
    }
}

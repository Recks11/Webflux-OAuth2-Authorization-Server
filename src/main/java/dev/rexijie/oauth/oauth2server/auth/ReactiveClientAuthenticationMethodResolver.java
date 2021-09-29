package dev.rexijie.oauth.oauth2server.auth;


import dev.rexijie.oauth.oauth2server.model.Client;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public interface ReactiveClientAuthenticationMethodResolver {
    Mono<ClientAuthenticationMethod> resolveClientAuthenticationMethod(ServerWebExchange exchange);
}

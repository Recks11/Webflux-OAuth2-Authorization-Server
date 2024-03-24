package dev.rexijie.oauth.oauth2server.auth;


import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public interface ReactiveClientAuthenticationMethodResolver {
    Mono<ClientAuthenticationMethod> resolveClientAuthenticationMethod(ServerWebExchange exchange);
}

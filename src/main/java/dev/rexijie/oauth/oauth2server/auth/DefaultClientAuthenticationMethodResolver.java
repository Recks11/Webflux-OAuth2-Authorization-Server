package dev.rexijie.oauth.oauth2server.auth;

import dev.rexijie.oauth.oauth2server.model.ClientUserDetails;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static org.springframework.security.oauth2.core.ClientAuthenticationMethod.NONE;


public class DefaultClientAuthenticationMethodResolver implements ReactiveClientAuthenticationMethodResolver {

    @Override
    public Mono<ClientAuthenticationMethod> resolveClientAuthenticationMethod(ServerWebExchange exchange) {
        return exchange.getPrincipal()
                .cast(Authentication.class)
                .map(Authentication::getDetails)
                .cast(ClientUserDetails.class)
                .map(clientUserDetails -> new ClientAuthenticationMethod(
                        clientUserDetails.clientData().tokenEndpointAuthMethod()))
                .switchIfEmpty(Mono.just(NONE));
    }
}

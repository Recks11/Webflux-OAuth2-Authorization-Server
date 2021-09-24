package dev.rexijie.oauth.oauth2server.auth;


import dev.rexijie.oauth.oauth2server.model.Client;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import reactor.core.publisher.Mono;

public interface ReactiveClientAuthenticationMethodResolver {
    Mono<ClientAuthenticationMethod> resolveClientAuthenticationMethod(Client client);
}

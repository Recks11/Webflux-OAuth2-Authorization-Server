package dev.rexijie.oauth.oauth2server.auth;

import dev.rexijie.oauth.oauth2server.model.Client;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import static org.springframework.security.oauth2.core.ClientAuthenticationMethod.*;
import reactor.core.publisher.Mono;

import java.util.Map;


public class DefaultClientAuthenticationMethodResolver implements ReactiveClientAuthenticationMethodResolver {
    Map<String, ClientAuthenticationMethod> clientAuthenticationMethodMap = Map.of(
            CLIENT_SECRET_BASIC.getValue(), CLIENT_SECRET_BASIC,
            CLIENT_SECRET_JWT.getValue(), CLIENT_SECRET_JWT,
            CLIENT_SECRET_POST.getValue(), CLIENT_SECRET_POST,
            PRIVATE_KEY_JWT.getValue(), PRIVATE_KEY_JWT
    );
    @Override
    public Mono<ClientAuthenticationMethod> resolveClientAuthenticationMethod(Client client) {
        return Mono.just(clientAuthenticationMethodMap.get(client.tokenEndpointAuthMethod()))
                .switchIfEmpty(Mono.just(NONE));
    }
}

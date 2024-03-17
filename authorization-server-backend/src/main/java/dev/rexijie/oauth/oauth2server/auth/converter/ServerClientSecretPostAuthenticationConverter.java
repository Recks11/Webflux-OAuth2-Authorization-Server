package dev.rexijie.oauth.oauth2server.auth.converter;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.api.domain.OAuth2AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.token.OAuth2Authentication;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static dev.rexijie.oauth.oauth2server.util.AuthenticationUtils.extractAuthenticationFromExchange;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.CLIENT_ID;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.CLIENT_SECRET;

public class ServerClientSecretPostAuthenticationConverter implements ServerAuthenticationConverter {


    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        return extractAuthenticationFromExchange(exchange)
                .flatMap(params -> {
                    String client_id = params.get(CLIENT_ID);
                    String client_secret = params.get(CLIENT_SECRET);

                    if (client_id == null) return Mono.empty();
                    if (client_secret != null){
                        var auth = new OAuth2Authentication(client_id, client_secret);
                        auth.setAuthorizationRequest(
                                new OAuth2AuthorizationRequest(
                                        AuthorizationRequest.from(params), null
                                )
                        );
                        return Mono.just(auth);
                    }

                    return needsPKCE(exchange);
                });
    }

    private Mono<Authentication> needsPKCE(ServerWebExchange exchange) {
        return Mono.empty();
    }
}

package dev.rexijie.oauth.oauth2server.auth.converter;

import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.CLIENT_ID;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.CLIENT_SECRET;

public class ServerClientSecretPostAuthenticationConverter implements ServerAuthenticationConverter {


    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        return extractParams(exchange)
                .flatMap(params -> {
                    String client_id = MultivaluedMapUtils.getFirstValue(params, CLIENT_ID);
                    String client_secret = MultivaluedMapUtils.getFirstValue(params, CLIENT_SECRET);

                    if (client_id == null) return Mono.empty();
                    if (client_secret != null)
                        return Mono.just(new UsernamePasswordAuthenticationToken(client_id, client_secret));

                    return needsPKCE(exchange);
                });
    }

    private Mono<Authentication> needsPKCE(ServerWebExchange exchange) {
        return Mono.empty();
    }

    private Mono<MultiValueMap<String, String>> extractParams(ServerWebExchange exchange) {
        return exchange.getFormData().switchIfEmpty(Mono.fromCallable(() -> exchange.getRequest().getQueryParams()));
    }
}

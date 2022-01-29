package dev.rexijie.oauth.oauth2server.util;

import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;

public class AuthenticationUtils {

    public static Mono<Map<String, String>> extractAuthenticationFromExchange(ServerWebExchange exchange) {
        return exchange.getFormData().map(map -> {
            if (map.size() == 0) return exchange.getRequest().getQueryParams();
            return map;
        }).map(MultiValueMap::toSingleValueMap);
    }
}

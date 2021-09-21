package dev.rexijie.oauth.oauth2server.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Authentication filter for the API endpoint and literally anything else
 */
@Component
public class ApiEndpointAuthenticationFilter implements WebFilter {

    private final ObjectMapper objectMapper;
    private final Set<String> ignoredPaths = new HashSet<>();

    public ApiEndpointAuthenticationFilter(
            ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        ignoredPaths.addAll(List.of("/oauth","/css","/js", "/openid"));
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        List<String> authorization = request.getHeaders().get(HttpHeaders.AUTHORIZATION);

        if ((authorization != null && authorization.contains("Bearer")) && !pathShouldBeIgnored(request.getPath().toString())) {
//            exchange.getResponse().writeWith();
        }

        return chain.filter(exchange);
    }

    protected void writeErrorResponse(ServerRequest request,
                                      ServerResponse response,
                                      Exception exception) throws IOException{
    }

    private boolean pathShouldBeIgnored(String path) {
        return ignoredPaths
                .stream()
                .anyMatch(path::startsWith);
    }
}

package dev.rexijie.oauth.oauth2server.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
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
    private final Set<String> applyTo = new HashSet<>();

    public ApiEndpointAuthenticationFilter(
            ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        applyTo.addAll(List.of("/api"));
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        List<String> authorization = request.getHeaders().get(HttpHeaders.AUTHORIZATION);

        if ((authorization != null && authorization.contains("Basic")) && !appliesTo(request.getPath().toString())) {
           try {
               SecurityContextHolder.getContext().setAuthentication(null);

           }catch (Exception ex) {
               SecurityContextHolder.getContext().setAuthentication(null);
               return Mono.empty();
           }
        }
        return chain.filter(exchange);
    }

    protected void writeErrorResponse(ServerRequest request,
                                      ServerResponse response,
                                      Exception exception) throws IOException{
    }

    private boolean appliesTo(String path) {
        return applyTo
                .stream()
                .anyMatch(path::startsWith);
    }
}

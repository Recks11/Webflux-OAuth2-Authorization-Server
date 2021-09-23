package dev.rexijie.oauth.oauth2server.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.rexijie.oauth.oauth2server.api.domain.ClientCredentials;
import dev.rexijie.oauth.oauth2server.services.ClientService;
import dev.rexijie.oauth.oauth2server.services.TokenServices;
import org.apache.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Authentication filter for the API endpoint and literally anything else
 */
//@Component
public class OAuth2EndpointAuthenticationFilter implements WebFilter {

    private final ObjectMapper objectMapper;
    private final TokenServices tokenServices;
    private final ClientService clientService;
    private final PasswordEncoder encoder;
    private final Set<String> applyTo = new HashSet<>();

    public OAuth2EndpointAuthenticationFilter(
            ObjectMapper objectMapper, TokenServices tokenServices, ClientService clientService, PasswordEncoder encoder) {
        this.objectMapper = objectMapper;
        this.tokenServices = tokenServices;
        this.clientService = clientService;
        this.encoder = encoder;
        applyTo.addAll(List.of("/oauth", "/openid"));
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        if (appliesTo(request.getPath().toString())) {
            Optional<String> authorizationOptional = request.getHeaders()
                    .getOrDefault(HttpHeaders.AUTHORIZATION, List.of())
                    .stream()
                    .filter(value -> value.toLowerCase().startsWith("basic"))
                    .findFirst();
            if (authorizationOptional.isEmpty())
                return Mono.error(createException("Anonymous users cannot interact with this server"));

            return Mono.just(authorizationOptional.get())
                    .map(this::extractCredentialsFromToken)
                    .flatMap(credentials -> clientService.findClientByWithCredentials(credentials)
                            .flatMap(clientDTO -> {
                                var authentication = new UsernamePasswordAuthenticationToken(credentials.clientId(), clientDTO);
                                SecurityContextHolder.getContext().setAuthentication(authentication);
                                return chain.filter(exchange);
                            })
                    ).doOnError(err -> {
                        SecurityContextHolder.getContext().setAuthentication(null);
                        throw Exceptions.propagate(createException("Invalid credentials"));
                    });
        }

        return chain.filter(exchange);
    }

    private boolean appliesTo(String path) {
        return applyTo
                .stream()
                .anyMatch(path::startsWith);
    }

    private ClientCredentials extractCredentialsFromToken(String authorizationHeader) {
        String token = authorizationHeader.substring(6);
        String decryptBasicToken = tokenServices.decryptBasicToken(token);
        String[] credentials = decryptBasicToken.split(":");
        return new ClientCredentials(credentials[0], encoder.encode(credentials[1]));
    }

    private OAuth2AuthenticationException createException(String message) {
        return new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT), message);
    }
}

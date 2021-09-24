package dev.rexijie.oauth.oauth2server.api.handlers;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

@Component
public class TokenEndpointHandler extends ApiEndpointHandler {
    private final ObjectMapper objectMapper;
    private final ReactiveAuthenticationManager authenticationManager;

    public TokenEndpointHandler(ObjectMapper objectMapper,
                                @Qualifier("userAuthenticationManager") ReactiveAuthenticationManager authenticationManager) {
        this.objectMapper = objectMapper;
        this.authenticationManager = authenticationManager;
    }

    //    private final


    public Mono<ServerResponse> getToken(ServerRequest request) {
        return ServerResponse.ok()
                .bodyValue(determineGrantTypeForRequest(request));
    }

    private String determineGrantTypeForRequest(ServerRequest request) {
        Map<String, Object> paramMap = new HashMap<>(request.queryParams().toSingleValueMap());
        AuthorizationRequest authenticationRequest = AuthorizationRequest.from(paramMap);
        handleAuthenticationRequest(authenticationRequest)
                .doOnNext(System.out::println)
                .doOnError(System.err::println)
                .subscribe();
        return authenticationRequest.getGrantType();
    }

    private Mono<Authentication> handleAuthenticationRequest(AuthorizationRequest request) {
        return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                "rexijie", "password"
        ));
    }
}

package dev.rexijie.oauth.oauth2server.api.handlers;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

@Component
public class TokenEndpointHandler extends ApiEndpointHandler {
    private final ObjectMapper objectMapper;

    public TokenEndpointHandler(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    //    private final


    public Mono<ServerResponse> getToken(ServerRequest request) {
        return ServerResponse.ok()
                .bodyValue(determineGrantTypeForRequest(request));
    }

    private AuthorizationRequest determineGrantTypeForRequest(ServerRequest request) {
        Map<String, Object> paramMap = new HashMap<>(request.queryParams().toSingleValueMap());
        return AuthorizationRequest.from(paramMap);
    }
}

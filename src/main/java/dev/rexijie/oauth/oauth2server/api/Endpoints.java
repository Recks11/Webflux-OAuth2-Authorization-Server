package dev.rexijie.oauth.oauth2server.api;

import dev.rexijie.oauth.oauth2server.api.handlers.*;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerResponse;

import java.util.Map;

import static org.springframework.web.reactive.function.server.RequestPredicates.all;
import static org.springframework.web.reactive.function.server.RequestPredicates.path;
import static org.springframework.web.reactive.function.server.RouterFunctions.route;

@Component
public class Endpoints {

    private static final String OAUTH_BASE_PATH = "/oauth";
    private static final String OIDC_BASE = "/openid";
    private static final String API_BASE = "/api";
    private static final String CLIENT_API_BASE = "/clients";
    private static final String USER_API_BASE = "/users";

    @Bean
    RouterFunction<ServerResponse> appRoutes(LandingHandler landingHandler,
                                             ClientEndpointHandler clientsHandler,
                                             UserEndpointHandler userHandler,
                                             TokenEndpointHandler tokenHandler,
                                             OpenIdConnectHandler oidcHandler
    ) {
        return authenticationServerApiEndpoints(landingHandler, clientsHandler, userHandler)
                .and(tokenEndpoints(tokenHandler))
                .and(oidcEndpoint(oidcHandler))
                .andRoute(all(), landingHandler::forbiddenResponse);
    }

    RouterFunction<ServerResponse> authenticationServerApiEndpoints(LandingHandler landingHandler,
                                                                 ClientEndpointHandler clientsHandler,
                                                                 UserEndpointHandler userHandler) {
        return route()
                .path(API_BASE, auth -> auth
                        .GET(path(""), landingHandler::homePage)
                        .path(CLIENT_API_BASE, clients -> clients
                                .POST(path(""), clientsHandler::createClient)
                        )
                        .path(USER_API_BASE, users -> users
                                .POST(path(""), userHandler::saveUser)
                                .GET("/{username}", userHandler::findUser)
                        )
                ).build();
    }

    RouterFunction<ServerResponse> authorizationEndpoints(TokenEndpointHandler tokenHandler) {
        return route()
                .path(OAUTH_BASE_PATH, home -> home
                        .POST("/authorize", request -> ServerResponse.ok().bodyValue(Map.of("uri", "authorize")))
                        .GET("/userinfo", request -> ServerResponse.ok().bodyValue(Map.of("uri", "userinfo")))
                        .GET("/introspect", request -> ServerResponse.ok().bodyValue(Map.of("uri", "introspect")))
                )
                .build();
    }

    RouterFunction<ServerResponse> tokenEndpoints(TokenEndpointHandler tokenHandler) {
        return route()
                .path(OAUTH_BASE_PATH, home -> home
                        .POST("/token", request -> ServerResponse.ok().bodyValue(Map.of("uri", "token")))
                        .GET("/token_key", request -> ServerResponse.ok().bodyValue(Map.of("uri", "token_key")))
                        .GET("/check_token", request -> ServerResponse.ok().bodyValue(Map.of("uri", "check token")))
                )
                .build();
    }

    // TODO(ADD CROSS ORIGIN)
    RouterFunction<ServerResponse> oidcEndpoint(OpenIdConnectHandler oidcHandler) {
        return route()
                .path(OIDC_BASE, home -> home
                        .GET(path("/.well-known/openid-configuration") ,oidcHandler::getOpenIdProperties)
                        .GET(path("/.well-known/jwks.json") ,oidcHandler::getJwkSet)
                )
                .build();
    }
}


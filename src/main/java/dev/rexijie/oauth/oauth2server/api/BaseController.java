package dev.rexijie.oauth.oauth2server.api;

import dev.rexijie.oauth.oauth2server.api.handlers.*;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.CacheControl;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerResponse;

import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.springframework.web.reactive.function.server.RequestPredicates.all;
import static org.springframework.web.reactive.function.server.RequestPredicates.path;
import static org.springframework.web.reactive.function.server.RouterFunctions.resources;
import static org.springframework.web.reactive.function.server.RouterFunctions.route;

@Component
public class BaseController {

    private static final String OAUTH_BASE_PATH = "/oauth";
    private static final String OIDC_BASE = "/openid";
    private static final String API_BASE = "/api";
    private static final String CLIENT_API_BASE = "/clients";
    private static final String USER_API_BASE = "/users";

    @Bean
    RouterFunction<ServerResponse> appRoutes(LandingHandler landingHandler,
                                             ClientEndpointHandler clientsHandler,
                                             UserEndpointHandler userHandler,
                                             AuthorizationEndpointHandler authorizationHandler,
                                             LoginAndApprovalHandler loginAndApprovalHandler,
                                             TokenEndpointHandler tokenHandler,
                                             OpenIdConnectHandler oidcHandler
    ) {
        return apiEndpoints(landingHandler, clientsHandler, userHandler)
                .and(oAuthTokenEndpoints(tokenHandler))
                .and(oidcEndpoint(oidcHandler))
                .and(oAuthAuthorizationEndpoints(authorizationHandler))
                .and(loginPage(loginAndApprovalHandler))
                .and(staticResources())
                .andRoute(all(), landingHandler::forbiddenResponse);
    }

    RouterFunction<ServerResponse> staticResources() {
        return resources("/static/**", new ClassPathResource("/static/"))
                .filter((request, next) -> {
                    var headers = request.exchange().getResponse().getHeaders();
                    headers.setCacheControl(CacheControl.maxAge(10, TimeUnit.MINUTES));
                    return next.handle(request);
                });
    }

    RouterFunction<ServerResponse> loginPage(LoginAndApprovalHandler loginAndApprovalHandler) {
        return route()
                .path("/", authorization -> authorization
                        .GET("login", loginAndApprovalHandler::indexPage)
                        .GET("approve", loginAndApprovalHandler::indexPage)
                ).build();
    }

    RouterFunction<ServerResponse> oAuthAuthorizationEndpoints(AuthorizationEndpointHandler authorizationEndpointHandler) {
        return route()
                .path(OAUTH_BASE_PATH, home -> home
                        .GET("/authorize", authorizationEndpointHandler::initiateAuthorization)
                        .POST("/authorize", authorizationEndpointHandler::authorizeRequest)
                        .path("/approve", approve -> approve
                                .GET( authorizationEndpointHandler::approvalPage)
                                .POST( authorizationEndpointHandler::approve)
                        )
                )
                .build();
    }

    RouterFunction<ServerResponse> oAuthTokenEndpoints(TokenEndpointHandler tokenHandler) {
        return route()
                .path(OAUTH_BASE_PATH, home -> home
                        .POST("/token", tokenHandler::getToken)
                        .GET("/token_key", tokenHandler::getTokenKey)
                        .GET("/check_token", request -> ServerResponse.ok().bodyValue(Map.of("uri", "check token")))
                        .GET("/userinfo", request -> ServerResponse.ok().bodyValue(Map.of("uri", "userinfo")))
                        .GET("/introspect", request -> request.principal().flatMap(p -> ServerResponse
                                .ok()
                                .bodyValue(p)))
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

    RouterFunction<ServerResponse> apiEndpoints(LandingHandler landingHandler,
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
}


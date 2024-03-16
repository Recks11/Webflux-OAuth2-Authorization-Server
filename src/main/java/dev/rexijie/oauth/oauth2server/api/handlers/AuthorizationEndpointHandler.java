package dev.rexijie.oauth.oauth2server.api.handlers;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.api.domain.OAuth2AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.auth.AuthenticationStage;
import dev.rexijie.oauth.oauth2server.config.OAuth2Properties;
import dev.rexijie.oauth.oauth2server.error.OAuthError;
import dev.rexijie.oauth.oauth2server.model.dto.ClientDTO;
import dev.rexijie.oauth.oauth2server.services.ReactiveAuthorizationCodeServices;
import dev.rexijie.oauth.oauth2server.token.OAuth2Authentication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.server.WebSession;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.net.URI;
import java.security.Principal;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static dev.rexijie.oauth.oauth2server.api.domain.ApiVars.PASSWORD_ATTRIBUTE;
import static dev.rexijie.oauth.oauth2server.api.domain.ApiVars.USERNAME_ATTRIBUTE;
import static dev.rexijie.oauth.oauth2server.util.UriUtils.modifyUri;
import static org.springframework.security.oauth2.core.OAuth2ErrorCodes.*;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.CODE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.STATE;


// Algorithm:
// 1. get authorization request
// 2. redirect to login page with session id
// 3. receive credentials and authenticate
// 4. on login, redirect to approve page
// 5. after approve, redirect to response with credentials
// TODO - Validate Referrer on ALL REDIRECTS
@Component
public class AuthorizationEndpointHandler extends OAuthEndpointHandler {
    private static final Logger LOG = LoggerFactory.getLogger(AuthorizationEndpointHandler.class);
    private static final String AUTHORIZATION_SESSION_AUTH_ATTRIBUTE = "dev.rexijie.oauth.SessionAuth";
    private static final String SCOPE_PREFIX = "scope:";

    @Value("classpath:/templates/index.html")
    private Resource index;
    private final ReactiveAuthorizationCodeServices authorizationCodeServices;
    private final ReactiveAuthenticationManager authenticationManager;
    private final OAuth2Properties oAuth2Properties;

    public AuthorizationEndpointHandler(ReactiveAuthorizationCodeServices reactiveAuthorizationCodeServices,
                                        @Qualifier("userAuthenticationManager") ReactiveAuthenticationManager authenticationManager, OAuth2Properties oAuth2Properties) {
        this.authorizationCodeServices = reactiveAuthorizationCodeServices;
        this.authenticationManager = authenticationManager;
        this.oAuth2Properties = oAuth2Properties;
    }

    private AuthorizationRequest validateAuthorizationRequest(Principal principal,
                                                              AuthorizationRequest request) {
        if (principal instanceof OAuth2Authentication clientAuthentication && clientAuthentication.getDetails() instanceof ClientDTO clientDto) {
            if (!clientDto.getRedirectUris().contains(request.getRedirectUri()))
                throw Exceptions.propagate(new OAuthError(OAuthError.OAuthErrors.INVALID_REQUEST,
                        "invalid client redirect uri"));

            return request;
        }

        throw Exceptions.propagate(new OAuth2AuthenticationException(
                new OAuth2Error(UNAUTHORIZED_CLIENT), "Client is not authorized"
        ));
    }


    // path GET /oauth/authorize
    public Mono<ServerResponse> initiateAuthorization(ServerRequest serverRequest) {
        if (serverRequest.queryParams().isEmpty()) return ServerResponse.badRequest().build();

        return extractAuthorizationFromParams(serverRequest)
                .zipWith(serverRequest.principal(),
                        (authorizationRequest, principal) -> validateAuthorizationRequest(principal, authorizationRequest))
                .flatMap(authorizationRequest -> serverRequest.session()
                        .flatMap(session -> {
                            if (!session.isStarted()) session.start();
                            LOG.info("started session: {}", session.getId());
                            session.getAttributes().put(
                                    AuthorizationRequest.AUTHORIZATION_SESSION_ATTRIBUTE, authorizationRequest);
                            return redirectTo(serverRequest, "/login");
                        }))
                .doOnError(throwable -> {
                    serverRequest.session().flatMap(WebSession::invalidate).subscribe();
                    LOG.error("error initialising authorization");
                });
    }

    // path POST /oauth/authorize
    public Mono<ServerResponse> authorizeRequest(ServerRequest request) {
        return request.session()
                .publishOn(Schedulers.boundedElastic())
                .zipWith(extractAuthorizationFromBody(request), (session, authorizationRequest) -> {
                    AuthorizationRequest storedRequest = session.getAttribute(AuthorizationRequest.AUTHORIZATION_SESSION_ATTRIBUTE);
                    if (storedRequest == null) {
                        session.invalidate().subscribe();
                        LOG.error("invalidating session with id {}", session.getId());
                        throw new OAuthError(null, "invalid_request", "Session not started"); // TODO (Make better error)
                    }

                    storedRequest.setAttribute(USERNAME_ATTRIBUTE, authorizationRequest.getAttribute(USERNAME_ATTRIBUTE));
                    storedRequest.setAttribute(PASSWORD_ATTRIBUTE, authorizationRequest.getAttribute(PASSWORD_ATTRIBUTE));
                    return storedRequest;
                })
                .flatMap(authorizationRequest -> authorize(authorizationRequest, request))
                .onErrorResume(err -> {
                    LOG.error("error authorizing user %s".formatted(err.getMessage()));
                    return redirectTo(request, "/login");
                });
    }

    private Mono<ServerResponse> authorize(AuthorizationRequest authorizationRequest, ServerRequest request) {
        String responseType = authorizationRequest.getResponseType();
        if (!responseType.equals(CODE)) return request.session()
                .doOnNext(WebSession::invalidate)
                .flatMap(session -> ServerResponse.badRequest().build());

        return request.session()
                .flatMap(session -> authenticateRequest(authorizationRequest)
                        .zipWith(request.principal(), (userAuthentication, principal) -> {
                            var auth = (OAuth2Authentication) principal;
                            auth.setAuthorizationRequest(new OAuth2AuthorizationRequest(
                                    authorizationRequest, userAuthentication));
                            auth.setAuthenticationStage(AuthenticationStage.PENDING_APPROVAL);
                            return auth;
                        })
                        .flatMap(authentication -> {
                            session.getAttributes().put(AUTHORIZATION_SESSION_AUTH_ATTRIBUTE, authentication);
                            return session.changeSessionId()
                                    .thenReturn(session);
                        })
                ).flatMap(s -> redirectTo(request, "%s/approve".formatted(oAuth2Properties.server().basePath())));
    }

    private Mono<Authentication> authenticateRequest(AuthorizationRequest authorizationRequest) {
        return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                        authorizationRequest.getAttributes().get(USERNAME_ATTRIBUTE),
                        authorizationRequest.getAttributes().get(PASSWORD_ATTRIBUTE)
                )).cast(OAuth2Authentication.class)
                .map(oAuth2Authentication -> {
                    oAuth2Authentication.setAuthenticationStage(AuthenticationStage.COMPLETE);
                    return oAuth2Authentication;
                });
    }

    /**
     * Get result from the approval request and create an approval code using the
     * {@link ReactiveAuthorizationCodeServices}
     */
    public Mono<ServerResponse> approve(ServerRequest request) {
        return request.session()
                .zipWith(request.formData().map(MultiValueMap::toSingleValueMap),
                        (session, approvalMap) -> {
                            OAuth2Authentication userAuth = session.getRequiredAttribute(AUTHORIZATION_SESSION_AUTH_ATTRIBUTE);
                            var storedRequest = userAuth.getAuthorizationRequest().storedRequest();
                            for (String scope : approvalMap.keySet()) {
                                boolean state = Boolean.parseBoolean(approvalMap.get(scope));
                                storedRequest.setAttribute("%s%s".formatted(SCOPE_PREFIX, scope), state);
                            }
                            return userAuth;
                        })
                .map(this::checkApproval)
                .publishOn(Schedulers.boundedElastic())
                .doOnError(throwable -> {
                    request.session().doOnNext(WebSession::invalidate).subscribe();
                    throw Exceptions.propagate(new OAuthError(throwable, 400, "unauthorized_client",
                            throwable.getMessage()));
                })
                .flatMap(fullAuthentication -> authorizationCodeServices.createAuthorizationCode(fullAuthentication)
                        .doOnNext(token -> LOG.info("generated token {}", token.toString()))
                        .flatMap(authorizationCode -> request.session().flatMap(session -> {
                            String redirectUri = fullAuthentication.getStoredRequest().getRedirectUri();
                            URI codeUri = modifyUri(redirectUri)
                                    .queryParam(CODE, authorizationCode.getCode())
                                    .queryParamIfPresent(STATE, Optional.of(fullAuthentication.getStoredRequest().getState()))
                                    .build();

                            return session.invalidate()
                                    .then(ServerResponse
                                            .temporaryRedirect(codeUri)
                                            .build());
                        })));

    }

    private String extractInvalidScopes(Set<String> original, Set<String> supplied) {

        return supplied.stream()
                .filter(s -> !original.contains(s))
                .reduce("", (s, s2) -> s.concat(" %s".formatted(s2)))
                .trim();
    }

    private OAuth2Authentication checkApproval(OAuth2Authentication authentication) {
        AuthorizationRequest storedRequest = authentication.getStoredRequest();
        Set<String> scopes = storedRequest.getScope();
        Set<String> requestAttributeKeySet = storedRequest.getAttributes().keySet();
        var scopesGranted = requestAttributeKeySet
                .stream().filter(key -> key.startsWith(SCOPE_PREFIX))
                .map(s -> s.replace(SCOPE_PREFIX, ""))
                .collect(Collectors.toSet());

        if (authentication.getDetails() instanceof ClientDTO dto) {
            if (!dto.getScopes().containsAll(scopes)) {
                throw new OAuth2AuthorizationException(
                        new OAuth2Error(INVALID_SCOPE),
                        "some requested scopes are invalid [%s]".formatted(extractInvalidScopes(dto.getScopes(), scopes)));
            }
        }

        if (!scopes.containsAll(scopesGranted)) throw new OAuth2AuthorizationException(
                new OAuth2Error(INVALID_SCOPE),
                "some requested scopes are invalid [%s]".formatted(extractInvalidScopes(scopes, scopesGranted)));

        Optional<Boolean> reduce = requestAttributeKeySet
                .stream().filter(key -> key.startsWith(SCOPE_PREFIX))
                .map(key -> Boolean.parseBoolean(storedRequest.getAttribute(key)))
                .reduce((s, s2) -> s && s2);

        if (reduce.isEmpty()) throw new OAuth2AuthorizationException(new OAuth2Error(INSUFFICIENT_SCOPE),
                "No Scopes were approved");

        if (!reduce.get()) throw new OAuth2AuthorizationException(new OAuth2Error(INSUFFICIENT_SCOPE),
                "Some Scopes were Rejected therefore, the token was discarded all together");
        return authentication;
    }

    public Mono<ServerResponse> approvalPage(ServerRequest request) {
        return ServerResponse.ok()
                .contentType(MediaType.TEXT_HTML)
                .bodyValue(index);
    }
}

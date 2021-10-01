package dev.rexijie.oauth.oauth2server.api.handlers;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.error.OAuthError;
import dev.rexijie.oauth.oauth2server.model.dto.ClientDTO;
import dev.rexijie.oauth.oauth2server.services.ReactiveAuthorizationCodeServices;
import dev.rexijie.oauth.oauth2server.token.OAuth2ApprovalAuthorizationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.server.WebSession;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Optional;

import static dev.rexijie.oauth.oauth2server.api.domain.ApiVars.PASSWORD_ATTRIBUTE;
import static dev.rexijie.oauth.oauth2server.api.domain.ApiVars.USERNAME_ATTRIBUTE;
import static dev.rexijie.oauth.oauth2server.util.UriUtils.modifyUri;
import static org.springframework.security.oauth2.core.OAuth2ErrorCodes.INSUFFICIENT_SCOPE;


// Algorithm:
// 1. get authorization request
// 2. redirect to login page with session id
// 3. receive credentials and authenticate
// 4. on login, redirect to approve page
// 5. after approve, redirect to response with credentials
@Component
public class AuthorizationEndpointHandler extends OAuthEndpointHandler {
    private static final Logger LOG = LoggerFactory.getLogger(AuthorizationEndpointHandler.class);
    private static final String AUTHORIZATION_SESSION_AUTH_ATTRIBUTE = "dev.rexijie.oauth.SessionAuth";

    @Value("classpath:/templates/index.html")
    private Resource index;
    private final ReactiveAuthorizationCodeServices authorizationCodeServices;
    private final ReactiveAuthenticationManager authenticationManager;

    public AuthorizationEndpointHandler(ReactiveAuthorizationCodeServices reactiveAuthorizationCodeServices,
                                        @Qualifier("userAuthenticationManager") ReactiveAuthenticationManager authenticationManager) {
        this.authorizationCodeServices = reactiveAuthorizationCodeServices;
        this.authenticationManager = authenticationManager;
    }


    // path GET /oauth/authorize
    public Mono<ServerResponse> initiateAuthorization(ServerRequest serverRequest) {
        if (serverRequest.queryParams().isEmpty()) return ServerResponse.badRequest().build();

        return extractAuthorizationFromParams(serverRequest)
                .zipWith(serverRequest.session(), (request, session) -> {
                    if (!session.isStarted()) session.start();
                    LOG.info("started session: {}", session.getId());
                    session.getAttributes().put(
                            AuthorizationRequest.AUTHORIZATION_SESSION_ATTRIBUTE, request);
                    return request;
                }).flatMap(request -> redirectTo(serverRequest, "/login"))
                .doOnError(throwable -> {
                    serverRequest.session().flatMap(WebSession::invalidate).subscribe();
                    LOG.error("error initialising authorization");
                });
    }

    // path POST /oauth/authorize
    public Mono<ServerResponse> authorizeRequest(ServerRequest request) {
        return request.session()
                .zipWith(extractAuthorizationFromBody(request), (session, authorizationRequest) -> {
                    Object storedRequest = session.getAttribute(AuthorizationRequest.AUTHORIZATION_SESSION_ATTRIBUTE);
                    if (storedRequest == null) {
                        session.invalidate().subscribe();
                        LOG.error("invalidating session with id {}", session.getId());
                        throw new OAuthError(null, "invalid_request", "Session not started"); // TODO (Make better error)
                    }

                    AuthorizationRequest authReq = (AuthorizationRequest) storedRequest;
                    authReq.getAttributes().putAll(authorizationRequest.getAttributes()); // add credentials to stored request
                    return authReq;
                })
                .flatMap(authorizationRequest -> authorize(authorizationRequest, request))
                .onErrorResume(err -> {
                    LOG.error("error authorizing user %s".formatted(err.getMessage()));
                    return redirectTo(request, "/login");
                });
    }

    private Mono<ServerResponse> authorize(AuthorizationRequest authorizationRequest, ServerRequest request) {
        String responseType = authorizationRequest.getResponseType();
        if (!responseType.equals("code")) return request.session()
                .doOnNext(WebSession::invalidate)
                .flatMap(session -> ServerResponse.badRequest().build());

        return request.session()
                .flatMap(session -> authenticateRequest(authorizationRequest)
                        .flatMap(authentication -> {
                            session.getAttributes().put(AUTHORIZATION_SESSION_AUTH_ATTRIBUTE, authentication);
                            return session.changeSessionId()
                                    .thenReturn(session);
                        })
                ).flatMap(s -> redirectTo(request, "/oauth/approve"));
    }

    private Mono<Authentication> authenticateRequest(AuthorizationRequest authorizationRequest) {
        return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                authorizationRequest.getAttributes().remove(USERNAME_ATTRIBUTE),
                authorizationRequest.getAttributes().remove(PASSWORD_ATTRIBUTE)
        )).map(authentication -> {
            var tk = new OAuth2ApprovalAuthorizationToken(
                    authentication.getPrincipal(),
                    authentication.getCredentials(),
                    authorizationRequest);
            tk.setAuthenticated(authentication.isAuthenticated());
            tk.setDetails(authentication.getDetails());
            return tk;
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
                            OAuth2ApprovalAuthorizationToken approvalToken = session.getRequiredAttribute(AUTHORIZATION_SESSION_AUTH_ATTRIBUTE);
                            for (String scope : approvalMap.keySet()) {
                                boolean state = Boolean.parseBoolean(approvalMap.get(scope));
                                if (state) approvalToken.approve(scope);
                            }
                            return approvalToken;
                        })
                .map(this::checkApproval)
                .doOnError(throwable -> {
                    request.session().doOnNext(WebSession::invalidate).subscribe();
                    throw Exceptions.propagate(new OAuthError(throwable, 400, "unauthorized_client",
                            "The user is not authorised to give approval"));
                })
                .flatMap(oAuth2ApprovalAuthorizationToken -> authorizationCodeServices.createAuthorizationCode(oAuth2ApprovalAuthorizationToken)
                        .doOnNext(token -> LOG.info("generated token {}", token.toString()))
                        .flatMap(t -> request.session().flatMap(se -> se.invalidate().thenReturn(t))) // invalidate session
                        .flatMap(token -> {
                            var clientDetails = (ClientDTO) token.getDetails(); // get cient details
                            var redirectUri = token.getAuthorizationRequest().getRedirectUri(); // get redirect uris

                            // validate redirect uri
                            if (!clientDetails.getRedirectUris().contains(redirectUri))
                                return Mono.error(new OAuthError(OAuthError.OAuthErrors.INVALID_REQUEST));

                            URI codeUri = modifyUri(redirectUri)
                                    .queryParam("code", token.getApprovalTokenId())
                                    .queryParamIfPresent("state", Optional.of(token.getAuthorizationRequest().getState()))
                                    .build();

                            return ServerResponse
                                    .temporaryRedirect(codeUri)
                                    .build();
                        }));

    }

    private OAuth2ApprovalAuthorizationToken checkApproval(OAuth2ApprovalAuthorizationToken token) {
        if (!token.isAllApproved()) throw new OAuth2AuthorizationException(new OAuth2Error(INSUFFICIENT_SCOPE));
        return token;
    }

    public Mono<ServerResponse> approvalPage(ServerRequest request) {
        return ServerResponse.ok()
                .contentType(MediaType.TEXT_HTML)
                .bodyValue(index);
    }
}

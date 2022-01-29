package dev.rexijie.oauth.oauth2server.api.handlers.flows;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import dev.rexijie.oauth.oauth2server.api.OAuthTest;
import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.api.domain.OAuth2AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.api.domain.OAuth2TokenResponse;
import dev.rexijie.oauth.oauth2server.auth.AuthenticationStage;
import dev.rexijie.oauth.oauth2server.auth.AuthorizationCodeWrapper;
import dev.rexijie.oauth.oauth2server.auth.EncryptedCodeAuthorizationCodeWrapper;
import dev.rexijie.oauth.oauth2server.config.OAuth2Properties;
import dev.rexijie.oauth.oauth2server.mocks.ModelMocks;
import dev.rexijie.oauth.oauth2server.security.keys.KeyPairStore;
import dev.rexijie.oauth.oauth2server.services.DefaultReactiveAuthorizationCodeServices;
import dev.rexijie.oauth.oauth2server.token.OAuth2Authentication;
import dev.rexijie.oauth.oauth2server.token.Signer;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.token.TokenService;
import org.springframework.test.web.reactive.server.FluxExchangeResult;
import org.springframework.web.reactive.function.BodyInserters;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.sql.Date;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static dev.rexijie.oauth.oauth2server.api.domain.ApiVars.Cookies.SESSION_COOKIE_NAME;
import static dev.rexijie.oauth.oauth2server.api.domain.ApiVars.PASSWORD_ATTRIBUTE;
import static dev.rexijie.oauth.oauth2server.api.domain.ApiVars.USERNAME_ATTRIBUTE;
import static dev.rexijie.oauth.oauth2server.token.claims.ClaimNames.Custom.AUTHORIZATION_REQUEST;
import static dev.rexijie.oauth.oauth2server.utils.TestUtils.returnsMonoAtArg;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.*;
import static org.springframework.security.oauth2.core.oidc.IdTokenClaimNames.NONCE;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class AuthorizationCodeFlowTests extends OAuthTest {
    private static final Map<String, ResponseCookie> responseCookieState = new HashMap<>();
    private static final String SESSION_ID = SESSION_COOKIE_NAME;
    @Autowired
    Signer signer;
    @Autowired
    private TokenService tokenService;
    @Autowired
    OAuth2Properties properties;

    @Override
    public void setUp() {
        when(codeRepository.save(any(AuthorizationCodeWrapper.class)))
                .then(returnsMonoAtArg());

        when(codeRepository.findByCode(any(String.class)))
                .thenReturn(getAuthenticationWrapper());
    }

    @Test
    @Order(1)
    void when_authorize_then_redirect_to_login() {

        URI authorizationUri = getUriBuilder().build();
        //initiate authorization
        FluxExchangeResult<Object> initialResponse = authClient()
                .get()
                .uri(authorizationUri)
                .exchange()
                .expectStatus().isTemporaryRedirect()
                .expectHeader().location(getUriBuilder().replacePath(LOGIN_ENDPOINT).build().toString())
                .expectCookie().exists(SESSION_ID)
                .returnResult(Object.class);

        ResponseCookie session = initialResponse.getResponseCookies().getFirst(SESSION_ID);

        responseCookieState.put(SESSION_ID, session);
    }

    @Test
    @Order(2)
    void when_login_expect_redirect_to_approval() {

        URI authorizationUri = getUriBuilder().build();
        var session = responseCookieState.get(SESSION_ID);
        // provide credentials
        FluxExchangeResult<Object> loginResult = authClient()
                .post()
                .uri(authorizationUri)
                .cookie(session.getName(), session.getValue())
                .body(BodyInserters
                        .fromFormData(USERNAME_ATTRIBUTE, "rexijie")
                        .with(PASSWORD_ATTRIBUTE, "password")
                )
                .exchange()
                .expectStatus().isTemporaryRedirect()
                .expectHeader().location(getUriBuilder().replacePath(APPROVAL_ENDPOINT).build().toString())
                .expectCookie().exists(SESSION_ID)
                .returnResult(Object.class);

        ResponseCookie newSession = loginResult.getResponseCookies().getFirst(SESSION_ID);
        responseCookieState.replace(SESSION_ID, newSession);
    }

    @Test
    @Order(3)
    void when_approval_then_redirect_to_redirect_uri() {
        var session = responseCookieState.get(SESSION_ID);
        // approve or deny scopes
        String clientUrlPattern = ModelMocks.testClient().registeredRedirectUris().toArray()[0].toString() + "(.)+";
        FluxExchangeResult<Object> approveDenyScopes = authClient()
                .post()
                .uri(getUriBuilder().replacePath(APPROVAL_ENDPOINT).build().toString())
                .body(BodyInserters.fromFormData("read", "true")
                        .with("write", "true"))
                .cookie(session.getName(), session.getValue())
                .exchange()
                .expectStatus().isTemporaryRedirect()
                .expectHeader().valuesMatch("Location", clientUrlPattern)
                .returnResult(Object.class);

        ResponseCookie scopesSession = approveDenyScopes.getResponseCookies().getFirst(SESSION_ID);
        responseCookieState.replace(SESSION_ID, scopesSession);
    }

    @Test
    @Order(4)
    void canGrantTokenWithAuthorizationCodeFlow() {
        // get token with authorization code
        FluxExchangeResult<OAuth2TokenResponse> tokenResponse = authClient()
                .post()
                .uri(TOKEN_ENDPOINT)
                .body(BodyInserters.
                        fromFormData(GRANT_TYPE, "authorization_code")
                        .with(CODE, "generated_code")
                        .with(CLIENT_ID, ModelMocks.testClient().clientId())
                        .with(REDIRECT_URI, ModelMocks.testClient().registeredRedirectUris().toArray(new String[]{})[0])
                        .with(SCOPE, "read write")
                        .with(NONCE, "random_nonce_string")
                        .with(STATE, "random_state"))
                .exchange()
                .expectStatus().isOk()
                .returnResult(OAuth2TokenResponse.class);

        StepVerifier.create(tokenResponse.getResponseBody())
                .assertNext(oAuth2TokenResponse -> {
                    assertThat(oAuth2TokenResponse.getScope().split(" ")).containsAll(List.of("read", "write"));
                    assertThat(oAuth2TokenResponse.getAccessToken()).isNotNull();
                    assertThat(oAuth2TokenResponse.getTokenType()).isEqualToIgnoringCase("bearer");
//                    assertThat(oAuth2TokenResponse.getRefreshToken()).isNotNull();
                })
                .verifyComplete();

    }

    @Test
    @Order(5)
    void when_anonymous_approval_then_redirect_to_redirect_uri() {
        // approve or deny scopes
        authClient()
                .post()
                .uri(getUriBuilder().replacePath(APPROVAL_ENDPOINT).build().toString())
                .body(BodyInserters
                        .fromFormData("read", "true")
                        .with("write", "true"))
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.BAD_REQUEST)
                .returnResult(Object.class);
    }

    private Mono<AuthorizationCodeWrapper> getAuthenticationWrapper() {
        var add = new DefaultReactiveAuthorizationCodeServices(null, null, null, null,
                null);

        return signer.sign(mockToken()).map(value -> new EncryptedCodeAuthorizationCodeWrapper("authentication_code",
                tokenService.allocateToken(add.createAdditionalInformation(value)).getKey()
                        .getBytes(StandardCharsets.UTF_8)));
    }

    private PlainJWT mockToken() {
        var client = ModelMocks.testClient();
        var user = ModelMocks.testUser();
        OAuth2Authentication authentication = ModelMocks.Authentication.createClientAuthentication(client);
        authentication.setAuthenticationStage(AuthenticationStage.COMPLETE);
        authentication.setAuthorizationRequest(new OAuth2AuthorizationRequest(
                AuthorizationRequest.from(Map.of(
                                GRANT_TYPE, "authorization_code",
                                REDIRECT_URI, client.registeredRedirectUris().toArray()[0].toString(),
                                CLIENT_ID, client.clientId(),
                                SCOPE, "read write",
                                STATE, "random_state",
                                NONCE, "random_nonce_string")),
                ModelMocks.Authentication.mockUserAuthentication(user)
        ));
        return new PlainJWT(
                new PlainHeader.Builder()
                        .customParams(Map.of(
                                Signer.SIGNING_KEY_ID, KeyPairStore.DEFAULT_KEY_NAME
                        )).build(),
                new JWTClaimsSet.Builder()
                        .subject(user.getUsername())
                        .jwtID("iqfbuhf89bo8fqwi9unf873fh8923")
                        .issuer(properties.openId().issuer())
                        .subject(authentication.getUserPrincipal().toString())
                        .audience(authentication.getPrincipal().toString())
                        .notBeforeTime(new Date(authentication.getAuthenticationTime()))
                        .claim(AUTHORIZATION_REQUEST,
                                new ObjectMapper().convertValue(authentication.getAuthorizationRequest().storedRequest(),
                                        new MapType<String, Object>()))
                        .claim(SCOPE, authentication.getAuthorizationRequest().storedRequest().getScope())
                        .issueTime(Date.from(Instant.now()))
                        .expirationTime(Date.from(Instant.now().plus(5, ChronoUnit.MINUTES)))
                        .build()
        );
    }

    private static class MapType<K, V> extends TypeReference<Map<K, V>> {}
}

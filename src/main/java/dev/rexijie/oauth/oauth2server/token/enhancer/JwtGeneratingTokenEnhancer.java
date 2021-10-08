package dev.rexijie.oauth.oauth2server.token.enhancer;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.api.domain.OAuth2AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.auth.AuthenticationStage;
import dev.rexijie.oauth.oauth2server.config.OAuth2Properties;
import dev.rexijie.oauth.oauth2server.generators.RandomStringSecretGenerator;
import dev.rexijie.oauth.oauth2server.generators.SecretGenerator;
import dev.rexijie.oauth.oauth2server.security.keys.KeyPairStore;
import dev.rexijie.oauth.oauth2server.token.OAuth2Authentication;
import dev.rexijie.oauth.oauth2server.token.Signer;
import dev.rexijie.oauth.oauth2server.util.JoseUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.token.Token;
import org.springframework.security.core.token.TokenService;
import org.springframework.security.oauth2.core.*;
import org.springframework.stereotype.Component;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

import java.sql.Date;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.security.oauth2.core.oidc.IdTokenClaimNames.AUTH_TIME;

/**
 * A JWT token enhancer that takes an {@link OAuth2AccessToken} and generates a serialized jwt access token, and refresh token.
 */
@Component
public class JwtGeneratingTokenEnhancer implements TokenEnhancer {
    private static final Logger LOG = LoggerFactory.getLogger(JwtGeneratingTokenEnhancer.class);
    private final OAuth2Properties properties;
    private final TokenService tokenService;
    private final Signer jwtSigner;
    private final SecretGenerator secretGenerator = new RandomStringSecretGenerator();
    ThreadLocal<ObjectMapper> om = ThreadLocal.withInitial(ObjectMapper::new);

    public JwtGeneratingTokenEnhancer(OAuth2Properties properties,
                                      TokenService tokenService,
                                      Signer jwtSigner) {
        this.properties = properties;
        this.tokenService = tokenService;
        this.jwtSigner = jwtSigner;
    }

    @Override
    public Mono<OAuth2Token> enhance(OAuth2AccessToken token, Authentication authentication) {
        if (authentication instanceof OAuth2Authentication oAuth2Authentication) {
            try {
                final PlainJWT jwtToken = switch (oAuth2Authentication.getAuthenticationStage()) {
                    case COMPLETE -> createToken(token, oAuth2Authentication);
                    case PENDING_APPROVAL -> createApprovalToken(token, oAuth2Authentication);
                    default -> throw new OAuth2AuthenticationException("Invalid Authentication");
                };

                return jwtSigner.sign(jwtToken)
                        .doOnError(throwable -> {
                            throw Exceptions.propagate(throwable);
                        })
                        .map(signedJwt -> {
                            try {
                                return createAccessToken(signedJwt, jwtToken.getJWTClaimsSet(), token);
                            } catch (ParseException e) {
                                throw Exceptions.propagate(e);
                            }
                        });
            } catch (OAuth2AuthenticationException ex) {
                return Mono.error(Exceptions.propagate(ex));
            }
        }
        return Mono.error(new OAuth2AuthenticationException("Invalid Authentication"));
    }

    @Override
    public Mono<Boolean> isEnhanced(OAuth2Token token) {
        return Mono.just(token).map(accessToken -> accessToken.getTokenValue().matches("(^[\\w-]*\\.[\\w-]*\\.[\\w-]*$)"));
    }

    @Override
    public Mono<OAuth2Authentication> readAuthentication(OAuth2Token auth2Token, OAuth2Authentication authentication) {
        return jwtSigner.deserialize(auth2Token.getTokenValue())
                .flatMap(signedJWT -> jwtSigner.verifyClaims(signedJWT, authentication)
                        .then(JoseUtils.extractClaimsSet(signedJWT))
                ).map(jwtClaimsSet -> {
                    try {
                        OAuth2Authentication auth = OAuth2Authentication.from(authentication);
                        if (!jwtClaimsSet.getAudience().contains(authentication.getPrincipal().toString()))
                            throw new OAuth2AuthorizationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT),
                                    "This client is unauthorized to use this code");
                        var auReq = jwtClaimsSet.getJSONObjectClaim("authorizationRequest");
                        var authReqString = JSONObjectUtils.toJSONString(auReq);
                        var authorizationRequest = getObjectMapper().readValue(authReqString, AuthorizationRequest.class);

                        auth.setAuthorizationRequest(new OAuth2AuthorizationRequest(
                                authorizationRequest,
                                new OAuth2Authentication(jwtClaimsSet.getSubject(), "from_code")
                        ));
                        auth.setAuthenticationStage(AuthenticationStage.COMPLETE);
                        return auth;
                    } catch (Exception exception) {
                        throw Exceptions.propagate(exception);
                    }
                });
    }

    private OAuth2AccessToken createAccessToken(String token, JWTClaimsSet claimSet, OAuth2AccessToken authToken) {
        return new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                token,
                claimSet.getIssueTime().toInstant(),
                claimSet.getExpirationTime().toInstant(),
                authToken.getScopes());
    }

    private PlainJWT createToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
        var tokenInfo = extractAdditionalInformationFromToken(token.getTokenValue());
        var jti = token.getTokenValue().substring(0, 32);
        var claimsSet = new JWTClaimsSet.Builder()
                .jwtID(jti)
                .issuer(properties.openId().issuer())
                .subject(tokenInfo.get("username"))
                .audience(authentication.getPrincipal().toString())
                .claim(AUTH_TIME, authentication.getAuthenticationTime())
                .notBeforeTime(Date.from(Instant.now()))
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plus(360, ChronoUnit.SECONDS)))
                .build();

        var header = createHeader(Map.of(
                "jti", jti,
                Signer.SIGNING_KEY_ID, KeyPairStore.DEFAULT_KEY_NAME));
        LOG.debug("Successfully Enhanced authentication token");
        return new PlainJWT(header, claimsSet);
    }

    private PlainJWT createApprovalToken(OAuth2AccessToken token, OAuth2Authentication authentication) {

        var payload = new JWTClaimsSet.Builder()
                .jwtID(secretGenerator.generate(24))
                .issuer(properties.openId().issuer())
                .subject(authentication.getUserPrincipal().toString())
                .audience(authentication.getPrincipal().toString())
                .notBeforeTime(Date.from(Instant.ofEpochSecond(authentication.getAuthenticationTime())))
                .claim("authorizationRequest",
                        getObjectMapper().convertValue(authentication.getAuthorizationRequest().storedRequest(),
                                new TypeReference<Map<String, Object>>() {
                                }))
                .claim("scopes", authentication.getAuthorizationRequest().storedRequest().getScopes())
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plus(5, ChronoUnit.MINUTES)))
                .build();
        LOG.debug("Successfully Enhanced approval token");
        return new PlainJWT(
                createHeader(Map.of(Signer.SIGNING_KEY_ID, KeyPairStore.DEFAULT_KEY_NAME)),
                payload
        );
    }

    private PlainHeader createHeader(Map<String, Object> otherParams) {
        return new PlainHeader.Builder() // set the key to use while signing
                .customParams(otherParams)
                .build();
    }

    private Map<String, String> extractAdditionalInformationFromToken(String value) {
        Token token = tokenService.verifyToken(value);
        var additionalInfo = token.getExtendedInformation();
        Map<String, String> entries = new HashMap<>();
        for (String entry : additionalInfo.split(",")) {
            String[] pair = entry.split("=");
            entries.put(pair[0], pair[1]);
        }

        return Collections.unmodifiableMap(entries);
    }

    private ObjectMapper getObjectMapper() {
        return om.get();
    }
}

package dev.rexijie.oauth.oauth2server.token.enhancer;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.api.domain.OAuth2AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.auth.AuthenticationStage;
import dev.rexijie.oauth.oauth2server.config.OAuth2Properties;
import dev.rexijie.oauth.oauth2server.model.dto.ClientDTO;
import dev.rexijie.oauth.oauth2server.token.OAuth2Authentication;
import dev.rexijie.oauth.oauth2server.token.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.token.Token;
import org.springframework.security.core.token.TokenService;
import org.springframework.security.oauth2.core.*;
import org.springframework.stereotype.Component;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

import java.sql.Date;
import java.text.ParseException;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static dev.rexijie.oauth.oauth2server.api.domain.OAuthVars.GrantTypes.CLIENT_CREDENTIALS;
import static dev.rexijie.oauth.oauth2server.token.claims.ClaimNames.Custom.*;
import static dev.rexijie.oauth.oauth2server.util.SerializationUtils.TypeReferences.mapTypeReference;
import static dev.rexijie.oauth.oauth2server.util.TimeUtils.minutesFromNow;
import static dev.rexijie.oauth.oauth2server.util.TimeUtils.secondsFromNow;
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
    private final ThreadLocal<ObjectMapper> om = ThreadLocal.withInitial(ObjectMapper::new);

    public JwtGeneratingTokenEnhancer(OAuth2Properties properties,
                                      TokenService tokenService,
                                      Signer jwtSigner) {
        this.properties = properties;
        this.tokenService = tokenService;
        this.jwtSigner = jwtSigner;
    }

    // TODO - Add Refresh Tokens
    @Override
    public Mono<OAuth2Token> enhance(OAuth2AccessToken token, Authentication authentication) {
        if (authentication instanceof OAuth2Authentication oAuth2Authentication) {
            try {
                final SignedJWT jwtToken = switch (oAuth2Authentication.getAuthenticationStage()) {
                    case COMPLETE -> createToken(token, oAuth2Authentication);
                    case PENDING_APPROVAL -> createApprovalToken(token, oAuth2Authentication);
                    default -> throw new OAuth2AuthenticationException("Invalid Authentication");
                };

                return jwtSigner.sign(jwtToken)
                        .doOnNext(s -> LOG.debug("Signing Token"))
                        .doOnSuccess(s -> LOG.debug("Successfully Signed Token"))
                        .doOnError(throwable -> {
                            throw Exceptions.propagate(throwable);
                        })
                        .map(signedJwt -> {
                            try {
                                return createAccessToken(signedJwt, jwtToken.getJWTClaimsSet(), token);
                            } catch (ParseException e) {
                                LOG.error("Error Signing Token");
                                throw Exceptions.propagate(e);
                            }
                        });
            } catch (OAuth2AuthenticationException ex) {
                LOG.error("an Error occured while Enhancing token");
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
                .map(jwt -> {
                    try {
                        var jwtClaimsSet = jwt.getJWTClaimsSet();
                        OAuth2Authentication auth = OAuth2Authentication.from(authentication);
                        if (!jwtClaimsSet.getAudience().contains(authentication.getPrincipal().toString()))
                            throw new OAuth2AuthorizationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT),
                                    "This client is unauthorized to use this code");
                        var auReq = jwtClaimsSet.getJSONObjectClaim(AUTHORIZATION_REQUEST);
                        var authReqString = JSONObjectUtils.toJSONString(auReq);
                        var authorizationRequest = getObjectMapper().readValue(authReqString, AuthorizationRequest.class);

                        auth.setAuthorizationRequest(new OAuth2AuthorizationRequest(
                                authorizationRequest,
                                new OAuth2Authentication(jwtClaimsSet.getSubject(), "from_code")
                        ));
                        auth.setAuthenticationStage(AuthenticationStage.COMPLETE);
                        return auth;
                    } catch (JsonProcessingException exception) {
                        LOG.error("Error reading Authentication from stored Token");
                        throw Exceptions.propagate(exception);
                    } catch (ParseException exception) {
                        LOG.error("Error retrieving AuthorizationRequest from Jwt Claims");
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

    private SignedJWT createToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
        String grantType = authentication.getStoredRequest().getGrantType();
        return grantType.equals(CLIENT_CREDENTIALS) ?
                createToken(createHeader(Map.of()), createClientClaimSet(token, authentication)) :
                createToken(createHeader(Map.of()), createUserClaimSet(token, authentication));
    }

    private SignedJWT createToken(JWSHeader header, JWTClaimsSet claimsSet) {
        return new SignedJWT(header, claimsSet);
    }

    private JWTClaimsSet createRefreshClaims(OAuth2AccessToken token, OAuth2Authentication authentication) {
        LOG.debug("Generating JWT Claims Set");
        var tokenInfo = extractAdditionalInformationFromToken(token.getTokenValue());
        var jti = getIdFromToken(token);
        ClientDTO details = authentication.getDetails(ClientDTO.class);

        return new JWTClaimsSet.Builder()
                .jwtID(jti)
                .issuer(properties.openId().issuer())
                .subject(tokenInfo.get("username"))
                .audience(authentication.getPrincipal().toString())
                .notBeforeTime(Date.from(Instant.ofEpochSecond(authentication.getAuthenticationTime())))
                .issueTime(Date.from(Instant.now()))
                .expirationTime(secondsFromNow(details.getRefreshTokenValidity()))
                .build();
    }

    private JWTClaimsSet createUserClaimSet(OAuth2AccessToken token, OAuth2Authentication authentication) {
        LOG.debug("Generating JWT Claims Set");
        var tokenInfo = extractAdditionalInformationFromToken(token.getTokenValue());
        var jti = getIdFromToken(token);
        ClientDTO details = authentication.getDetails(ClientDTO.class);

        JWTClaimsSet userClaims = new JWTClaimsSet.Builder()
                .jwtID(jti)
                .issuer(properties.openId().issuer())
                .subject(tokenInfo.get("username"))
                .audience(authentication.getPrincipal().toString())
                .claim(AUTH_TIME, authentication.getAuthenticationTime())
                .claim(SCOPES, authentication.getStoredRequest().getScope())
                .claim(AUTHORITIES, authentication.getUserAuthentication()
                        .getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority).collect(Collectors.toSet()))
                .issueTime(Date.from(Instant.now()))
                .expirationTime(secondsFromNow(details.getAccessTokenValidity()))
                .notBeforeTime(Date.from(Instant.now()))
                .build();
        return addFinalClaims(userClaims, authentication);
    }

    private JWTClaimsSet createClientClaimSet(OAuth2AccessToken token, OAuth2Authentication authentication) {
        var tokenInfo = extractAdditionalInformationFromToken(token.getTokenValue());
        var jti = getIdFromToken(token);


        JWTClaimsSet clientClaims = new JWTClaimsSet.Builder()
                .jwtID(jti)
                .issuer(properties.openId().issuer())
                .subject(tokenInfo.get("username"))
                .audience(authentication.getPrincipal().toString())
                .claim(AUTH_TIME, authentication.getAuthenticationTime())
                .claim(SCOPES, authentication.getStoredRequest().getScope())
                .build();
        return addFinalClaims(clientClaims, authentication);
    }

    private SignedJWT createApprovalToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
        AuthorizationRequest storedRequest = authentication.getAuthorizationRequest().storedRequest();
        var payload = new JWTClaimsSet.Builder()
                .jwtID(getIdFromToken(token))
                .issuer(properties.openId().issuer())
                .subject(authentication.getUserPrincipal().toString())
                .audience(authentication.getPrincipal().toString())
                .claim(AUTHORIZATION_REQUEST, getObjectMapper().convertValue(storedRequest, mapTypeReference()))
                .claim(SCOPES, authentication.getAuthorizationRequest().storedRequest().getScope())
                .issueTime(Date.from(Instant.now()))
                .expirationTime(minutesFromNow(3))
                .notBeforeTime(Date.from(Instant.ofEpochSecond(authentication.getAuthenticationTime())))
                .build();
        LOG.debug("Successfully Enhanced approval token");
        return new SignedJWT(createHeader(Map.of()),
                payload
        );
    }

    private JWTClaimsSet addFinalClaims(JWTClaimsSet claimsSet, OAuth2Authentication authentication) {
        ClientDTO details = authentication.getDetails(ClientDTO.class);
        return new JWTClaimsSet.Builder(claimsSet)
                .notBeforeTime(Date.from(Instant.ofEpochSecond(authentication.getAuthenticationTime())))
                .issueTime(Date.from(Instant.now()))
                .expirationTime(secondsFromNow(details.getAccessTokenValidity()))
                .build();
    }

    private JWSHeader createHeader(Map<String, Object> otherParams) {
        // TODO - change algorithm based on parameter
        return new JWSHeader.Builder(JWSAlgorithm.RS256) // set the key to use while signing
                .type(JOSEObjectType.JWT)
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

    private String getIdFromToken(OAuth2Token token) {
        return token.getTokenValue().substring(0, 32);
    }
}

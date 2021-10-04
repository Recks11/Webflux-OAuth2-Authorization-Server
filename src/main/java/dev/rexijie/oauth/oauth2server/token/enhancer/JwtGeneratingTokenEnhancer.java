package dev.rexijie.oauth.oauth2server.token.enhancer;

import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import dev.rexijie.oauth.oauth2server.config.OAuth2Properties;
import dev.rexijie.oauth.oauth2server.security.keys.KeyPairStore;
import dev.rexijie.oauth.oauth2server.token.Signer;
import dev.rexijie.oauth.oauth2server.util.TimeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.token.Token;
import org.springframework.security.core.token.TokenService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.stereotype.Component;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

import java.sql.Date;
import java.text.ParseException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * A JWT token enhancer that takes an {@link OAuth2AccessToken} and generates a serialized jwt access token, and refresh token.
 *
 *
 */
@Component
public class JwtGeneratingTokenEnhancer implements TokenEnhancer {
    private static final Logger LOG = LoggerFactory.getLogger(JwtGeneratingTokenEnhancer.class);
    private final OAuth2Properties properties;
    private final TokenService tokenService;
    private final Signer jwtSigner;

    public JwtGeneratingTokenEnhancer(OAuth2Properties properties,
                                      TokenService tokenService,
                                      Signer jwtSigner) {
        this.properties = properties;
        this.tokenService = tokenService;
        this.jwtSigner = jwtSigner;
    }

    @Override
    public Mono<OAuth2Token> enhance(OAuth2AccessToken token, Authentication authentication) {
        var jwtToken = enhanceToken(token, authentication);
        return jwtSigner.sign(jwtToken)
                .doOnError(throwable -> {throw Exceptions.propagate(throwable);})
                .map(signedJwt -> {
                    try {
                        return new OAuth2AccessToken(
                                OAuth2AccessToken.TokenType.BEARER,
                                signedJwt,
                                jwtToken.getJWTClaimsSet().getIssueTime().toInstant(),
                                jwtToken.getJWTClaimsSet().getExpirationTime().toInstant(),
                                token.getScopes());
                    } catch (ParseException e) {
                        throw Exceptions.propagate(e);
                    }
                });
    }

    private PlainJWT enhanceToken(OAuth2AccessToken token, Authentication authentication) {
        var tokenInfo = extractAdditionalInformationFromToken(token.getTokenValue());
        var claimsSet = new JWTClaimsSet.Builder()
                .jwtID(token.getTokenValue().substring(0, 32))
                .issuer(properties.openId().issuer())
                .subject(tokenInfo.get("username"))
                .audience(authentication.getPrincipal().toString())
                .claim("auth_time", TimeUtils.localDateTimeToEpochSecond(LocalDateTime.now()))
                .notBeforeTime(Date.from(Instant.now()))
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plus(360, ChronoUnit.SECONDS)))
                .build();

        var header = new PlainHeader.Builder()
                .customParam(Signer.SIGNING_KEY_ID, KeyPairStore.DEFAULT_KEY_NAME)
                .build();
        LOG.debug("Successfully Enhanced authentication token");
        return new PlainJWT(header, claimsSet);
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
}

package dev.rexijie.oauth.oauth2server.util;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.time.Instant;
import java.util.HashSet;
import java.util.Objects;

public class JoseUtils {
    public static OAuth2AccessToken fromNimbusdsToken(AccessToken token) {
        return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                token.getValue(),
                Instant.now(),
                Instant.now().plusSeconds(token.getLifetime()),
                new HashSet<>(token.getScope().toStringList()));
    }

    public static BearerAccessToken toNimbusdsToken(OAuth2AccessToken token) {
        return new BearerAccessToken(
                token.getTokenValue(),
                Objects.requireNonNull(token.getExpiresAt()).
                        minusSeconds(Objects.requireNonNull(token.getIssuedAt()).
                                getEpochSecond()).getEpochSecond(),
                new Scope()
        );
    }

    public static Mono<JWTClaimsSet> extractClaimsSet(JWT token) {
        return Mono.create(jwtClaimsSetMonoSink -> {
            try {
                var claims = token.getJWTClaimsSet();
                jwtClaimsSetMonoSink.success(claims);
            } catch (ParseException exception) {
                jwtClaimsSetMonoSink.error(exception);
            }
        });
    }
}

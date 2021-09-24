package dev.rexijie.oauth.oauth2server.util;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

import java.time.Instant;
import java.util.HashSet;
import java.util.Objects;

public class TokenUtils {
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
}

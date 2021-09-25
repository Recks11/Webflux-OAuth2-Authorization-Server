package dev.rexijie.oauth.oauth2server.converter;

import dev.rexijie.oauth.oauth2server.config.OAuth2Properties;
import dev.rexijie.oauth.oauth2server.util.TimeUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.Set;

@Component
public class JwtGeneratingTokenEnhancer implements TokenEnhancer {

    private final OAuth2Properties properties;

    public JwtGeneratingTokenEnhancer(OAuth2Properties properties) {
        this.properties = properties;
    }

    @Override
    public Mono<OAuth2Token> enhance(OAuth2AccessToken token, Authentication authentication) {
        Jwt.withTokenValue(token.getTokenValue())
                .issuedAt(token.getIssuedAt())
                .expiresAt(token.getExpiresAt())
                .subject(extractSubject(authentication))
                .issuer(properties.openId().issuer())
                .jti(token.getTokenValue())
                .claim("auth_time", TimeUtils.localDateTimeToEpochSecond(LocalDateTime.now()))
                .notBefore(token.getIssuedAt())
                .audience(Set.of("{client_id}")) // or resource id if available
                .build();
        return null;
    }

    private String extractSubject(Authentication authentication) {
        return "username";
    }
}

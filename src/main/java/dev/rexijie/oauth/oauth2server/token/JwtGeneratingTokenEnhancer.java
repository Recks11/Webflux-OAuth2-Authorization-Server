package dev.rexijie.oauth.oauth2server.token;

import dev.rexijie.oauth.oauth2server.config.OAuth2Properties;
import dev.rexijie.oauth.oauth2server.util.TimeUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.token.TokenService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Component
public class JwtGeneratingTokenEnhancer implements TokenEnhancer {

    private final OAuth2Properties properties;
    private final TokenService tokenService;

    public JwtGeneratingTokenEnhancer(OAuth2Properties properties,
                                      TokenService tokenService) {
        this.properties = properties;
        this.tokenService = tokenService;
    }

    @Override
    public Mono<OAuth2Token> enhance(OAuth2AccessToken token, Authentication authentication) {
        var tokenInfo = extractAdditionalInformationFromToken(token.getTokenValue());
        Jwt.withTokenValue(token.getTokenValue())
                .issuedAt(token.getIssuedAt())
                .expiresAt(token.getExpiresAt())
                .subject(tokenInfo.get("username"))
                .issuer(properties.openId().issuer())
                .jti(token.getTokenValue())
                .claim("auth_time", TimeUtils.localDateTimeToEpochSecond(LocalDateTime.now()))
                .notBefore(token.getIssuedAt())
                .audience(Set.of("{client_id}")) // or resource id if available
                .build();
        return Mono.just(token);
    }

    private void signToken() {

    }

    private Map<String, String> extractAdditionalInformationFromToken(String value) {
        Map<String, String> entries = new HashMap<>();
        for (String entry : value.split(",")) {
            String[] pair = entry.split("=");
            entries.put(pair[0], pair[1]);
        }

        return Collections.unmodifiableMap(entries);
    }
}

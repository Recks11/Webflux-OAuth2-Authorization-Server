package dev.rexijie.oauth.oauth2server.token.enhancer;

import com.nimbusds.jwt.JWTClaimsSet;
import dev.rexijie.oauth.oauth2server.config.OAuth2Properties;
import dev.rexijie.oauth.oauth2server.token.NimbusdsJoseServices;
import dev.rexijie.oauth.oauth2server.util.TimeUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.token.Token;
import org.springframework.security.core.token.TokenService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.stereotype.Component;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

import java.sql.Date;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtGeneratingTokenEnhancer implements TokenEnhancer {

    private final OAuth2Properties properties;
    private final TokenService tokenService;
    private final NimbusdsJoseServices joseServices;

    public JwtGeneratingTokenEnhancer(OAuth2Properties properties,
                                      TokenService tokenService,
                                      NimbusdsJoseServices joseServices) {
        this.properties = properties;
        this.tokenService = tokenService;
        this.joseServices = joseServices;
    }

    @Override
    public Mono<OAuth2Token> enhance(OAuth2AccessToken token, Authentication authentication) {
        var jwtToken = createClaimSet(token, authentication);
        return joseServices.sign(jwtToken)
                .doOnError(throwable -> {throw Exceptions.propagate(throwable);})
                .map(signedJwt -> new OAuth2AccessToken(
                        OAuth2AccessToken.TokenType.BEARER,
                        signedJwt,
                        jwtToken.getIssueTime().toInstant(),
                        jwtToken.getExpirationTime().toInstant(),
                        token.getScopes()));
    }

    private JWTClaimsSet createClaimSet(OAuth2AccessToken token, Authentication authentication) {
        var tokenInfo = extractAdditionalInformationFromToken(token.getTokenValue());
        return new JWTClaimsSet.Builder()
                .jwtID(token.getTokenValue().substring(0, 32))
                .issuer(properties.openId().issuer())
                .subject(tokenInfo.get("username"))
                .audience(authentication.getPrincipal().toString())
                .claim("auth_time", TimeUtils.localDateTimeToEpochSecond(LocalDateTime.now()))
                .notBeforeTime(Date.from(Instant.now()))
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plus(360, ChronoUnit.SECONDS)))
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
}

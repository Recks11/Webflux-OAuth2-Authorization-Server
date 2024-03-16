package dev.rexijie.oauth.oauth2server.mocks;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.rexijie.oauth.oauth2server.api.domain.ClientCredentials;
import dev.rexijie.oauth.oauth2server.config.OAuth2Properties;
import dev.rexijie.oauth.oauth2server.generators.ClientCredentialsGenerator;
import dev.rexijie.oauth.oauth2server.generators.CredentialsGenerator;
import dev.rexijie.oauth.oauth2server.generators.RandomStringSecretGenerator;
import org.springframework.security.core.token.KeyBasedPersistenceTokenService;
import org.springframework.security.core.token.SecureRandomFactoryBean;
import org.springframework.security.core.token.TokenService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

public class ServiceMocks {

    public static class ConfigBeans {

        public static CredentialsGenerator<ClientCredentials> credentialsGenerator() {
            return new ClientCredentialsGenerator(new RandomStringSecretGenerator());
        }
        public static ObjectMapper testObjectMapper() {
            return new ObjectMapper();
        }

        public static TokenService testTokenService() {

            var tokenService = new KeyBasedPersistenceTokenService();
            tokenService.setServerSecret("stoke-serbert");
            tokenService.setServerInteger(42001);
            tokenService.setPseudoRandomNumberBytes(64);
            try {
                tokenService.setSecureRandom(new SecureRandomFactoryBean().getObject());
            } catch (Exception exception) {
                //
            }

            return tokenService;
        }

        public static OAuth2Properties mockProperties () {
            return new OAuth2Properties(
                    new OAuth2Properties.OAuth2ServerProperties(
                            "test-server",
                            "test-secret",
                            2010,
                            true,
                            "/oauth"
                    ),
                    new OAuth2Properties.OidcProperties(
                            "http://localhost:8010",
                            "/oauth",
                            "https://localhost:8010",
                            "https://localhost:8010/oauth/token",
                            "https://localhost:8010/oauth/token_key",
                            "https://localhost:8010/oauth/authorize",
                            "https://localhost:8010/oauth/check_token",
                            "https://localhost:8010/oauth/user_info",
                            "https://localhost:8010/oauth/introspect",
                            "https://localhost:8010/.well_known/jwks.json",
                            "https://localhost:8010/oauth/revoke",
                            Set.of("RS256"),
                            Set.of("RS256"), Set.of("RS256"),
                            Set.of("openid", "profile", "email", "read", "write"),
                            Set.of("public"),
                            Set.of("code"), Set.of("iss", "sub", "iat", "azp", "exp", "scope", "at_hash", "nonce"),
                            Set.of("authorization_code", "implicit"),
                            Set.of("client_secret_basic", "client_secret_post")
                    )
            );
        }

        public static PasswordEncoder testPasswordEncoder() {
            return new BCryptPasswordEncoder();
        }
    }
}

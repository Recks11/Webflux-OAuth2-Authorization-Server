package dev.rexijie.oauth.oauth2server.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import dev.rexijie.oauth.oauth2server.generators.KeyGen;
import dev.rexijie.oauth.oauth2server.security.keys.KeyPairContainer;
import dev.rexijie.oauth.oauth2server.security.keys.KeyPairStore;
import dev.rexijie.oauth.oauth2server.security.keys.InMemoryRSAKeyPairStore;
import dev.rexijie.oauth.oauth2server.token.NimbusdsJoseTokenSigner;
import dev.rexijie.oauth.oauth2server.token.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.token.KeyBasedPersistenceTokenService;
import org.springframework.security.core.token.SecureRandomFactoryBean;
import org.springframework.security.core.token.TokenService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Configuration
public class SecurityEncryptionConfig {
    private static final Logger LOG = LoggerFactory.getLogger(SecurityEncryptionConfig.class);

    @Bean
    @Primary
    public TokenService tokenService(OAuth2Properties properties) {
        try {
            var secureRandom = new SecureRandomFactoryBean().getObject();
            var toS = new KeyBasedPersistenceTokenService();
            toS.setSecureRandom(secureRandom);
            toS.setServerInteger(properties.server().randomInt());
            toS.setServerSecret(properties.server().secret());
            return toS;
        } catch (Exception ex) {
            LOG.error("Error creating enhanced token service, falling back to default");
            return new KeyBasedPersistenceTokenService();
        }
    }

    @Bean
    public TokenService authorizationCodeTokenServices(OAuth2Properties properties) {
        try {
            var secureRandom = new SecureRandomFactoryBean().getObject();
            var toS = new KeyBasedPersistenceTokenService();
            toS.setPseudoRandomNumberBytes(8);
            toS.setSecureRandom(secureRandom);
            toS.setServerInteger(properties.server().randomInt());
            toS.setServerSecret(properties.server().secret());
            return toS;
        } catch (Exception ex) {
            LOG.error("Error creating enhanced token service, falling back to default");
            return new KeyBasedPersistenceTokenService();
        }
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public KeyPairStore<RSAPrivateKey, RSAPublicKey> rsaKeyStore() {
        return new InMemoryRSAKeyPairStore(KeyGen.generateKeys());
    }

    @Bean
    public Signer jwtSigner() {
        return new NimbusdsJoseTokenSigner(rsaKeyStore());
    }

    @Bean
    public JWKSet jwkSet() {
        KeyPairContainer keyPair = rsaKeyStore().getDefault();
        RSAKey build = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.parse(keyPair.getKeyAlgorithm()))
                .keyID(rsaKeyStore().getId())
                .build();
        return new JWKSet(build);
    }
}

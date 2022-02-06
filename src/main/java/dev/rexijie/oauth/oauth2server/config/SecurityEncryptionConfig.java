package dev.rexijie.oauth.oauth2server.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSAlgorithmFamilyJWSKeySelector;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import dev.rexijie.oauth.oauth2server.generators.KeyGen;
import dev.rexijie.oauth.oauth2server.token.NimbusJOSETokenProcessor;
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

import java.util.List;

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
    public TokenService authorizationCodeTokenService(OAuth2Properties properties) {
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
    public JWKSet jwkSet() {
        var ecKey = KeyGen.generateECKey();
        var rsaKey = KeyGen.generateRSAJWK();
        return new JWKSet(List.of(ecKey, rsaKey));
    }

    @Bean
    public JWKSource<SecurityContext> keySource() {
        return new ImmutableJWKSet<>(jwkSet());
    }

    @Bean
    public JWSKeySelector<SecurityContext> keySelectorBean() {
        try {
            return JWSAlgorithmFamilyJWSKeySelector.fromJWKSource(new ImmutableJWKSet<>(jwkSet().toPublicJWKSet()));
        } catch (KeySourceException e) {
            LOG.error("KeySource Error", e);
            return new JWSAlgorithmFamilyJWSKeySelector<>(JWSAlgorithm.Family.RSA, keySource());
        }
    }

    @Bean
    public NimbusJOSETokenProcessor jwtSigner() {
        return new NimbusJOSETokenProcessor(keySelectorBean(), keySource());
    }
}

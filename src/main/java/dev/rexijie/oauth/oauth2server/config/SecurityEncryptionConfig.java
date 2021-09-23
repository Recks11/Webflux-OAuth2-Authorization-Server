package dev.rexijie.oauth.oauth2server.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import dev.rexijie.oauth.oauth2server.generators.KeyGen;
import dev.rexijie.oauth.oauth2server.keys.KeyPairStore;
import dev.rexijie.oauth.oauth2server.keys.RSAKeyPairStore;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Configuration
public class SecurityEncryptionConfig {


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public KeyPairStore rsaKeyStore() throws Exception {
        return new RSAKeyPairStore(KeyGen.generateKeys());
    }

    @Bean
    public JWKSet jwkSet(KeyPairStore keyPairStore) {
        RSAKey.Builder builder = new RSAKey.Builder(keyPairStore.getPublicKey(RSAPublicKey.class))
                .privateKey(keyPairStore.getPrivateKey(RSAPrivateKey.class))
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .keyID(keyPairStore.getId());

        return new JWKSet(builder.build());
    }
}

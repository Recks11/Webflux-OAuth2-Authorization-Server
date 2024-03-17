package dev.rexijie.oauth.oauth2server.generators;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.stereotype.Component;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Factory for generating random String keys.
 * It makes use of {@link SecureRandom} to generate random bytes
 * of a given length
 *
 * @author Rex Ijiekhuamen
 */

@Component
public class RandomStringSecretGenerator implements SecretGenerator {
    private static final Logger LOG = LoggerFactory.getLogger(RandomStringSecretGenerator.class);
    final int DEFAULT_KEY_LENGTH = 32;
    private final int bytesKeyLength;

    public RandomStringSecretGenerator() {
        this.bytesKeyLength = this.DEFAULT_KEY_LENGTH;
    }

    public RandomStringSecretGenerator(int bytesKeyLength) {
        this.bytesKeyLength = bytesKeyLength;
    }

    @Override
    public String generate() {
        return generate(bytesKeyLength);
    }

    @Override
    public String generate(int length) {
        char[] charEncodedBytes = Hex.encode(generateBytes(length));
        return new String(charEncodedBytes);
    }

    private byte[] generateBytes(int byteLength) {
        SecureRandom secureRandom;
        try {
            secureRandom = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException ex) {
            LOG.warn("No Strong secure algorithm available in JDK, switching to default instance");
            secureRandom = new SecureRandom();
        }

        byte[] bytes = new byte[byteLength];
        secureRandom.nextBytes(bytes);

        return bytes;
    }
}

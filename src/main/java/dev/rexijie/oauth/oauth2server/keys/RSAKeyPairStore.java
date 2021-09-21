package dev.rexijie.oauth.oauth2server.keys;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.UUID;

public class RSAKeyPairStore implements KeyPairStore {
    private final String id;
    private final KeyPair keyPair;

    public RSAKeyPairStore(KeyPair keyPair) {
        this.id = UUID.randomUUID().toString();
        this.keyPair = keyPair;
    }

    @Override
    public String getId() {
        return this.id;
    }

    @Override
    public <K1 extends PrivateKey> K1 getPrivateKey(Class<K1> keyClass) {
        return keyClass.cast(keyPair.getPrivate());
    }

    @Override
    public <K2 extends PublicKey> K2 getPublicKey(Class<K2> keyClass) {
        return keyClass.cast(keyPair.getPublic());
    }
}

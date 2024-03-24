package dev.rexijie.oauth.oauth2server.security.keys;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.UUID;

public class KeyPairContainer {
    private final String id;
    private final KeyPair keys;
    private final String keyUse;
    private final String keyAlgorithm;

    public KeyPairContainer(KeyPair keys, String keyAlgorithm) {
        this(UUID.randomUUID().toString(), keys, "sig", keyAlgorithm);
    }

    public KeyPairContainer(KeyPair keys, String keyUse, String keyAlgorithm) {
        this(UUID.randomUUID().toString(), keys, keyUse, keyAlgorithm);
    }

    public KeyPairContainer(String id, KeyPair keys, String keyUse, String keyAlgorithm) {
        this.id = id;
        this.keys = keys;
        this.keyUse = keyUse;
        this.keyAlgorithm = keyAlgorithm;
    }

    public String getId() {
        return id;
    }

    public KeyPair getKeys() {
        return keys;
    }

    public String getKeyUse() {
        return keyUse;
    }

    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public PublicKey getPublic() {
        return keys.getPublic();
    }

    public PrivateKey getPrivate() {
        return keys.getPrivate();
    }
}

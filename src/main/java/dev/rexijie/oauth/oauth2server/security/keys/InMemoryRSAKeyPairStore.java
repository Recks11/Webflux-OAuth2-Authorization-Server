package dev.rexijie.oauth.oauth2server.security.keys;

import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import static org.springframework.security.oauth2.jose.jws.JwsAlgorithms.RS256;

public class InMemoryRSAKeyPairStore implements KeyPairStore<RSAPrivateKey, RSAPublicKey> {
    public static final String DEFAULT_KEY = "default";
    Map<String, KeyPairContainer> keyPairMap = new ConcurrentHashMap<>();

    public InMemoryRSAKeyPairStore(KeyPair keyPair) {
        this.keyPairMap.put(DEFAULT_KEY, new KeyPairContainer(DEFAULT_KEY, keyPair, "sig", RS256));
    }

    @Override
    public String getId() {
        return DEFAULT_KEY;
    }

    @Override
    public KeyPairContainer getDefault() {
        return keyPairMap.get(DEFAULT_KEY);
    }

    @Override
    public KeyPairContainer getKeyPair(String id) {
        return keyPairMap.get(id);
    }

    @Override
    public String addKeyPair(KeyPair keyPair, String keyUse, String alg) throws KeyStoreException {
        if (keyPair.getPrivate() instanceof RSAPrivateKey &&
                keyPair.getPublic() instanceof RSAPublicKey)
            throw new KeyStoreException("Invalid Keys");
        var key = UUID.randomUUID().toString();
        this.keyPairMap.put(key, new KeyPairContainer(keyPair, keyUse, alg));
        return key;
    }

    @Override
    public void removeKeyPair(String keyID) {
        this.keyPairMap.remove(keyID);
    }

    public RSAPublicKey getPublicKey(String id) {
        return (RSAPublicKey) keyPairMap.get(getId()).getPublic();
    }

    public RSAPrivateKey getPrivateKey(String id) {
        return (RSAPrivateKey) keyPairMap.get(id).getPrivate();
    }
}

package dev.rexijie.oauth.oauth2server.security.keys;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import static org.springframework.security.oauth2.jose.jws.JwsAlgorithms.RS256;

public class InMemoryRSAKeyPairStore implements KeyPairStore<RSAPrivateKey, RSAPublicKey> {
    private static final Logger LOG = LoggerFactory.getLogger(InMemoryRSAKeyPairStore.class);
    Map<String, KeyPairContainer> keyPairMap = new ConcurrentHashMap<>();

    public InMemoryRSAKeyPairStore(KeyPair keyPair) {
        try {
            addKeyPair(DEFAULT_KEY_NAME, keyPair, "sig", RS256);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }

    @Override
    public boolean canStore(KeyPairContainer container) {
        return container.getPrivate() instanceof RSAPrivateKey &&
                container.getPublic() instanceof RSAPublicKey;
    }

    @Override
    public String getId() {
        return DEFAULT_KEY_NAME;
    }

    @Override
    public KeyPairContainer getDefault() {
        return keyPairMap.get(DEFAULT_KEY_NAME);
    }

    @Override
    public KeyPairContainer getKeyPair(String id) {
        return keyPairMap.get(id);
    }

    @Override
    public String addKeyPair(KeyPair keyPair, String keyUse, String alg) throws KeyStoreException {
        var key = UUID.randomUUID().toString();
        addKeyPair(key, keyPair, keyUse, alg);
        return key;
    }

    private void addKeyPair(String id, KeyPair keyPair, String keyUse, String alg) throws KeyStoreException {
        var container = new KeyPairContainer(id, keyPair, keyUse, alg);
        if (!canStore(container)) throw new KeyStoreException("Invalid Keys");
        this.keyPairMap.put(id, container);
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

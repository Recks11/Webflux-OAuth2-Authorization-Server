package dev.rexijie.oauth.oauth2server.keys.context;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.proc.JWKSecurityContext;

import java.util.List;

public class KeyContext extends JWKSecurityContext {

    /**
     * Constructs a {@code JWKSecurityContext} with the provided
     * parameters.
     *
     * @param keys The list of keys.
     */
    public KeyContext(List<JWK> keys) {
        super(keys);
    }
}

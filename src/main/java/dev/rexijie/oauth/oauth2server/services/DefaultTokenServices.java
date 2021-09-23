package dev.rexijie.oauth.oauth2server.services;

import org.springframework.stereotype.Component;

import java.util.Base64;

@Component
public class DefaultTokenServices implements TokenServices {

    @Override
    public Object createAccessToken() {
        return null;
    }

    @Override
    public Object refreshAccessToken() {
        return null;
    }

    @Override
    public Object getAccessToken() {
        return null;
    }

    @Override
    public String decryptBasicToken(String value) {
        return new String(Base64.getDecoder().decode(value));
    }
}

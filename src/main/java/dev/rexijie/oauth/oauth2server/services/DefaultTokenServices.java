package dev.rexijie.oauth.oauth2server.services;

import org.springframework.stereotype.Component;

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
}

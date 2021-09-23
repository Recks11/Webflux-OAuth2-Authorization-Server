package dev.rexijie.oauth.oauth2server.services;

import org.springframework.stereotype.Component;

@Component
public interface TokenServices {
    Object createAccessToken();
    Object refreshAccessToken();
    Object getAccessToken();
    String decryptBasicToken(String value);
}

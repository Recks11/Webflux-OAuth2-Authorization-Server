package dev.rexijie.oauth.oauth2server.converter;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

public interface TokenEnhancer {
    OAuth2AccessToken enhance(OAuth2AccessToken token, Authentication authentication);
}

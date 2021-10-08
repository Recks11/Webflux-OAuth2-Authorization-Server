package dev.rexijie.oauth.oauth2server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.server.session.CookieWebSessionIdResolver;
import org.springframework.web.server.session.DefaultWebSessionManager;
import org.springframework.web.server.session.WebSessionIdResolver;
import org.springframework.web.server.session.WebSessionManager;

import java.time.Duration;

import static dev.rexijie.oauth.oauth2server.api.domain.ApiVars.Cookies.SESSION_COOKIE_NAME;

@Configuration
public class SessionConfig {

    public WebSessionIdResolver webSessionIdResolver() {
        CookieWebSessionIdResolver resolver = new CookieWebSessionIdResolver();
        resolver.setCookieName(SESSION_COOKIE_NAME);
        resolver.addCookieInitializer((builder) -> builder.path("/")
                .sameSite("Strict")
                .maxAge(Duration.ofMinutes(5))
                .httpOnly(true));

        return resolver;
    }

    @Bean
    public WebSessionManager webSessionManager() {
        DefaultWebSessionManager webSessionManager = new DefaultWebSessionManager();
        webSessionManager.setSessionIdResolver(webSessionIdResolver());
        return webSessionManager;
    }
}

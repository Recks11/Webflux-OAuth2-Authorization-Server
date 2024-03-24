package dev.rexijie.oauth.oauth2server.util;

import org.springframework.web.util.DefaultUriBuilderFactory;
import org.springframework.web.util.UriBuilder;
import org.springframework.web.util.UriBuilderFactory;

import java.net.URI;

public class UriUtils {
    private static final UriBuilderFactory factory = new DefaultUriBuilderFactory();
    private static final Object object = new Object();

    public static UriBuilder modifyUri(String path) {
        synchronized (object) {
            URI uri = URI.create(path);
            return factory.builder()
                    .scheme(uri.getScheme())
                    .host(uri.getHost())
                    .port(uri.getPort())
                    .fragment(uri.getFragment())
                    .query(uri.getQuery())
                    .userInfo(uri.getUserInfo())
                    .path(uri.getPath());
        }
    }
}

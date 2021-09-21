package dev.rexijie.oauth.oauth2server.util;

import reactor.core.Exceptions;

public class ExceptionUtils {

    public static void propagate(Throwable t) {
        throw Exceptions.propagate(t);
    }
}

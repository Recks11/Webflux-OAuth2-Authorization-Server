package dev.rexijie.oauth.oauth2server.error;

import org.springframework.boot.autoconfigure.web.ErrorProperties;
import org.springframework.boot.autoconfigure.web.WebProperties;
import org.springframework.boot.autoconfigure.web.reactive.error.DefaultErrorWebExceptionHandler;
import org.springframework.boot.web.reactive.error.ErrorAttributes;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

import java.util.Map;

public class OAuthErrorWebExceptionHandler extends DefaultErrorWebExceptionHandler {
    public OAuthErrorWebExceptionHandler(ErrorAttributes errorAttributes, WebProperties.Resources resources,
                                         ErrorProperties errorProperties, ApplicationContext applicationContext) {
        super(errorAttributes, resources, errorProperties, applicationContext);
    }

    @Override
    protected Mono<ServerResponse> renderErrorResponse(ServerRequest request) {
        Throwable error = getError(request);
        if (error instanceof StatusAwareException exception) {
            Map<String, Object> errorAttrs = getErrorAttributes(request, getErrorAttributeOptions(request, MediaType.ALL));
            return ServerResponse.status(exception.getStatus())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(BodyInserters.fromValue(errorAttrs));
        }
        return super.renderErrorResponse(request);
    }
}

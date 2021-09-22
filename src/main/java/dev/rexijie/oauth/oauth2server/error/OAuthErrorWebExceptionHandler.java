package dev.rexijie.oauth.oauth2server.error;

import org.apache.http.HttpHeaders;
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

    /**
     * Render the error response as JSON
     */
    @Override
    protected Mono<ServerResponse> renderErrorResponse(ServerRequest request) {
        Map<String, Object> errorAttributes = getErrorAttributes(request, getErrorAttributeOptions(request, MediaType.ALL));
        Object path = errorAttributes.remove("path");
        String errorPath = "/errors";
        if (path != null) errorPath = (String) path;
        return ServerResponse
                .status(getHttpStatus(errorAttributes))
                .contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.LOCATION, errorPath)
                .body(BodyInserters.fromValue(errorAttributes));
    }

    @Override
    protected int getHttpStatus(Map<String, Object> errorAttributes) {
        return (int) errorAttributes.remove("status");
    }
}

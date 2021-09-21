package dev.rexijie.oauth.oauth2server.error;

import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.reactive.error.DefaultErrorAttributes;
import org.springframework.boot.web.reactive.error.ErrorAttributes;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.server.ServerWebExchange;

import java.util.Map;

public class OAuthErrorAttributes implements ErrorAttributes {
    //    private static final String ERROR_INTERNAL_ATTRIBUTE = DefaultErrorAttributes.class.getName() + ".ERROR";
    private ErrorAttributes delegate = new DefaultErrorAttributes();

    @Override
    public Map<String, Object> getErrorAttributes(ServerRequest request, ErrorAttributeOptions options) {
        var error = getError(request);
        Map<String, Object> errorAttributes = delegate.getErrorAttributes(request, options);
        if (error instanceof OAuthError authError) {
            errorAttributes.clear();
            errorAttributes.put("error", authError.getError());
            errorAttributes.put("error_description", authError.getErrorDescription());
        }

        if (error instanceof ApiError apiError) {
            errorAttributes.clear();
            errorAttributes.put("error", apiError.getReason());
        }
        return errorAttributes;
    }

    @Override
    public Throwable getError(ServerRequest request) {
        return delegate.getError(request);
    }

    @Override
    public void storeErrorInformation(Throwable error, ServerWebExchange exchange) {
        delegate.storeErrorInformation(error, exchange);
    }

    public void setDelegate(ErrorAttributes delegate) {
        this.delegate = delegate;
    }
}

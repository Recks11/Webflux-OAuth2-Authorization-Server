package dev.rexijie.oauth.oauth2server.error;

import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.reactive.error.ErrorAttributes;
import org.springframework.context.MessageSource;
import org.springframework.core.annotation.MergedAnnotation;
import org.springframework.core.annotation.MergedAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

public class OAuthErrorAttributes implements ErrorAttributes {
    //    private static final String ERROR_INTERNAL_ATTRIBUTE = DefaultErrorAttributes.class.getName() + ".ERROR";
    private ErrorAttributes delegate;
    private final MessageSource messageSource;

    public OAuthErrorAttributes(ErrorAttributes delegate, MessageSource messageSource) {
        this.delegate = delegate;
        this.messageSource = messageSource;
    }


    @Override
    public Map<String, Object> getErrorAttributes(ServerRequest request, ErrorAttributeOptions options) {
        Map<String, Object> errorAttributes = new LinkedHashMap<>();
        var error = getError(request);

        errorAttributes.put("status", determineHttpStatus(error));
        errorAttributes.put("path", request.path());
        if (error instanceof OAuthError authError) {
            errorAttributes.put("error", authError.getError());
            errorAttributes.put("error_description", authError.getErrorDescription());
        }

        if (error instanceof ApiError apiError) {
            errorAttributes.put("reason", apiError.getReason());
        }

        if (error instanceof DtoValidationException exception) {
            Map<String, Object> fieldErrorMap = new LinkedHashMap<>();
            var fieldErrors = exception.getFieldErrors();
            for (FieldError err: fieldErrors) {
                var field = err.getField();
                var defaultMessage = err.getDefaultMessage();
                var message = defaultMessage;
                var codes = err.getCodes();
                if (codes != null) {
                    for (String code : codes) {
                        message = messageSource.getMessage(code, null, defaultMessage, Locale.ENGLISH);
                        if (message != null && !message.equals(defaultMessage)) break;
                    }
                }
                fieldErrorMap.put(field, message);
            }
            errorAttributes.put("message", "There are errors in the provided object");
            errorAttributes.put("errors", fieldErrorMap);
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

    private int determineHttpStatus(Throwable error) {
        if (error instanceof ResponseStatusException rse) return rse.getStatus().value();
        Optional<HttpStatus> responseStatusAnnotation  = getResponseStatusAnnotation(error);
        if (responseStatusAnnotation.isPresent()) return responseStatusAnnotation.get().value();
        if (error instanceof StatusAwareException sae) return sae.getStatus();
        return 500;
    }

    private Optional<HttpStatus> getResponseStatusAnnotation(Throwable throwable) {
        MergedAnnotation<ResponseStatus> responseStatusMergedAnnotation = MergedAnnotations
                .from(throwable.getClass(), MergedAnnotations.SearchStrategy.TYPE_HIERARCHY).get(ResponseStatus.class);
        return responseStatusMergedAnnotation.getValue("code", HttpStatus.class);
    }


}

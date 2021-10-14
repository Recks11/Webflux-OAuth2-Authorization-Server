package dev.rexijie.oauth.oauth2server.auth;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.*;


public class DefaultClientAuthenticationMethodResolver implements ReactiveClientAuthenticationMethodResolver {

    @Override
    public Mono<ClientAuthenticationMethod> resolveClientAuthenticationMethod(ServerWebExchange exchange) {
        return determineClientAuthenticationMethod(exchange);
    }

    private Mono<ClientAuthenticationMethod> determineClientAuthenticationMethod(ServerWebExchange exchange) {
        return Mono.just(exchange.getRequest())
                .flatMap(request -> {
                    // Check for client secret basic
                    var authorization = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
                    if (authorization != null && authorization.toLowerCase().startsWith("basic"))
                        return Mono.just(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);

                    // The other methods require HTTP POST with URL-encoded params
                    if (request.getMethod() != HttpMethod.POST) {
                        var contentType = request.getHeaders().getContentType();
                        if (contentType != null && contentType.includes(MediaType.APPLICATION_FORM_URLENCODED))
                            return Mono.just(ClientAuthenticationMethod.NONE); // no auth
                    }

                    return exchange.getFormData()
                            .switchIfEmpty(Mono.fromCallable(() -> exchange.getRequest().getQueryParams()))
                            .map(params -> {
                                // We have client secret post
                                if (StringUtils.isNotBlank(MultivaluedMapUtils.getFirstValue(params, CLIENT_ID)) &&
                                        StringUtils.isNotBlank(MultivaluedMapUtils.getFirstValue(params, CLIENT_SECRET))) {
                                    return ClientAuthenticationMethod.CLIENT_SECRET_POST;
                                }

                                // Do we have a signed JWT assertion?
                                if (StringUtils.isNotBlank(MultivaluedMapUtils.getFirstValue(params, CLIENT_ASSERTION)) &&
                                        StringUtils.isNotBlank(MultivaluedMapUtils.getFirstValue(params, CLIENT_ASSERTION_TYPE))) {
                                    return ClientAuthenticationMethod.CLIENT_SECRET_JWT;
                                }

                                return ClientAuthenticationMethod.NONE;
                            });
                });
    }
}

package dev.rexijie.oauth.oauth2server.auth;

import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;


public class DefaultClientAuthenticationMethodResolver implements ReactiveClientAuthenticationMethodResolver {

    @Override
    public Mono<ClientAuthenticationMethod> resolveClientAuthenticationMethod(ServerWebExchange exchange) {
        return Mono.fromCallable(() -> determineClientAuthenticationMethod(exchange));
    }

    private ClientAuthenticationMethod determineClientAuthenticationMethod(ServerWebExchange exchange) {
        var request = exchange.getRequest();
        // Check for client secret basic
        var authorization = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorization != null && authorization.toLowerCase().startsWith("basic"))
            return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;

        // The other methods require HTTP POST with URL-encoded params
        if (request.getMethod() != HttpMethod.POST) {
            var contentType = request.getHeaders().getContentType();
            if (contentType != null && contentType.includes(MediaType.APPLICATION_FORM_URLENCODED))
                return ClientAuthenticationMethod.NONE; // no auth
        }

        Map<String, List<String>> params = request.getQueryParams();

        // We have client secret post
        if (StringUtils.isNotBlank(MultivaluedMapUtils.getFirstValue(params, "client_id")) &&
                StringUtils.isNotBlank(MultivaluedMapUtils.getFirstValue(params, "client_secret"))) {
            return ClientAuthenticationMethod.CLIENT_SECRET_POST;
        }

        // Do we have a signed JWT assertion?
        if (StringUtils.isNotBlank(MultivaluedMapUtils.getFirstValue(params, "client_assertion")) &&
                StringUtils.isNotBlank(MultivaluedMapUtils.getFirstValue(params, "client_assertion_type"))) {
            return ClientAuthenticationMethod.CLIENT_SECRET_JWT;
        }

        return ClientAuthenticationMethod.NONE;
    }
}

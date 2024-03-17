package dev.rexijie.oauth.oauth2server.security.filters;

import dev.rexijie.oauth.oauth2server.auth.AuthenticationServerAuthenticationConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

public class ClientAuthenticationResolutionFilter implements WebFilter {
    private static final Logger LOG = LoggerFactory.getLogger(ClientAuthenticationResolutionFilter.class);
    private ServerAuthenticationConverter converter = new AuthenticationServerAuthenticationConverter();

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .switchIfEmpty(converter.convert(exchange)
                        .switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
                        .flatMap(authentication -> {
                            SecurityContext securityContext = new SecurityContextImpl(authentication);
                            LOG.debug("Populated SecurityContext with authentication token: '{}'", authentication);
                            return chain.filter(exchange)
                                    .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext)))
                                    .then(Mono.empty());
                        }))
                .flatMap((securityContext) -> {
                    LOG.debug("handling request in filter");
                    return chain.filter(exchange);
                });
    }

    public void setConverter(ServerAuthenticationConverter converter) {
        this.converter = converter;
    }
}

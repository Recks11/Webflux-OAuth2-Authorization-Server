package dev.rexijie.oauth.oauth2server.auth.manager;

import dev.rexijie.oauth.oauth2server.model.ClientUserDetails;
import dev.rexijie.oauth.oauth2server.token.OAuth2Authentication;
import org.springframework.security.authentication.AbstractUserDetailsReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import reactor.core.publisher.Mono;

public class ReactiveClientAuthenticationManager extends AbstractUserDetailsReactiveAuthenticationManager {

    private final ReactiveUserDetailsService clientDetailsService;

    public ReactiveClientAuthenticationManager(ReactiveUserDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }


    @Override
    protected Mono<UserDetails> retrieveUser(String clientId) {
        return this.clientDetailsService.findByUsername(clientId);
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        return super.authenticate(authentication)
                .map(this::convertTokenToOAuth2Token);
    }

    private OAuth2Authentication convertTokenToOAuth2Token(Authentication authentication) {
        ClientUserDetails clientUserDetails = (ClientUserDetails) authentication.getPrincipal();
        OAuth2Authentication auth = new OAuth2Authentication(clientUserDetails.clientData().clientId(),
                authentication.getCredentials(),
                authentication.getAuthorities());
        auth.setAuthenticated(authentication.isAuthenticated());
        auth.setDetails(clientUserDetails.clientData());
        return auth;
    }


}

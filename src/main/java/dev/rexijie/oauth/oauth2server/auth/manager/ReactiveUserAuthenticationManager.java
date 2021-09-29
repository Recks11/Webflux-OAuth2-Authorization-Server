package dev.rexijie.oauth.oauth2server.auth.manager;

import dev.rexijie.oauth.oauth2server.auth.AuthenticationStage;
import dev.rexijie.oauth.oauth2server.model.User;
import dev.rexijie.oauth.oauth2server.token.OAuth2Authentication;
import org.springframework.security.authentication.AbstractUserDetailsReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import reactor.core.publisher.Mono;

public class ReactiveUserAuthenticationManager extends AbstractUserDetailsReactiveAuthenticationManager {

    private final ReactiveUserDetailsService userDetailsService;

    public ReactiveUserAuthenticationManager(ReactiveUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }


    @Override
    protected Mono<UserDetails> retrieveUser(String clientId) {
        return this.userDetailsService.findByUsername(clientId);
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        return super.authenticate(authentication)
                .map(this::convertTokenToOAuth2Token);
    }

    private OAuth2Authentication convertTokenToOAuth2Token(Authentication authentication) {
        User user = (User) authentication.getPrincipal();
        user.setPassword(null);
        OAuth2Authentication auth = new OAuth2Authentication(user.getUsername(),
                "[YOU THOUGHT]",
                authentication.getAuthorities());
        auth.setAuthenticated(authentication.isAuthenticated());
        auth.setAuthenticationStage(AuthenticationStage.COMPLETE);
        auth.setDetails(user);
        return auth;
    }


}

package dev.rexijie.oauth.oauth2server.auth.manager;

import dev.rexijie.oauth.oauth2server.model.ClientUserDetails;
import dev.rexijie.oauth.oauth2server.token.OAuth2Authentication;
import org.springframework.security.authentication.AbstractUserDetailsReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import reactor.core.publisher.Mono;

import static dev.rexijie.oauth.oauth2server.api.domain.ApiVars.CLIENT_AUTHENTICATION_METHOD;
import static dev.rexijie.oauth.oauth2server.model.dto.ClientDTO.ClientMapper.toDto;

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
                .map(auth -> mergeAuthentication(auth, authentication));
    }

    private OAuth2Authentication mergeAuthentication(Authentication authenticatedAuth, Authentication initialAuth) {
        ClientUserDetails clientUserDetails = (ClientUserDetails) authenticatedAuth.getPrincipal();

        OAuth2Authentication auth = new OAuth2Authentication(clientUserDetails.clientData().clientId(),
                "[YOU THOUGHT!!]",
                authenticatedAuth.getAuthorities());
        auth.setAuthenticated(authenticatedAuth.isAuthenticated());
        if (initialAuth instanceof OAuth2Authentication iAuth) {
            auth.setAuthorizationRequest(iAuth.getAuthorizationRequest());
        }
        auth.setDetails(toDto(clientUserDetails.clientData()));

        String tokenEndpointAuthenticationMethod = clientUserDetails.clientData().tokenEndpointAuthMethod();
        if (tokenEndpointAuthenticationMethod == null) tokenEndpointAuthenticationMethod = "none";

        auth.getStoredRequest().setAttribute(CLIENT_AUTHENTICATION_METHOD, tokenEndpointAuthenticationMethod);
        return auth;
    }


}

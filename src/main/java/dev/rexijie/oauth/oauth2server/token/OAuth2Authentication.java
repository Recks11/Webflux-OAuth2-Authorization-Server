package dev.rexijie.oauth.oauth2server.token;

import com.fasterxml.jackson.annotation.JsonIgnore;
import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.api.domain.OAuth2AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.auth.AuthenticationStage;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;

import java.io.Serial;
import java.util.Collection;

/**
 * Authentication that holds both the user and client userAuthentication.
 * The principal for this authenticaiton is the client id.
 * other information of the client is stored in the client details as {@link dev.rexijie.oauth.oauth2server.model.Client}
 */
public class OAuth2Authentication extends AbstractAuthenticationToken {
    @Serial
    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
    private AuthenticationStage authenticationStage;
    private final Object principal;
    private Object credentials;
    @JsonIgnore
    private OAuth2AuthorizationRequest authorizationRequest;

    public OAuth2Authentication(Object principal, Object credentials) {
        this(principal, credentials, null);
    }

    /**
     * Creates a token with the supplied array of authorities.
     *
     * @param authorities the collection of <tt>GrantedAuthority</tt>s for the principal
     *                    represented by this userAuthentication object.
     * @param credentials the credentials of the authorized client
     */
    public OAuth2Authentication(Object principal, Object credentials,
                                Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        this.authenticationStage = AuthenticationStage.STARTED;
    }

    public OAuth2Authentication(Object principal, Object credentials,
                                Collection<? extends GrantedAuthority> authorities,
                                OAuth2AuthorizationRequest authorizationRequest) {
        this(principal, credentials, authorities);
        this.authorizationRequest = authorizationRequest;
    }

    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    public OAuth2AuthorizationRequest getAuthorizationRequest() {
        return this.authorizationRequest;
    }

    public void setAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest) {
        this.authorizationRequest = authorizationRequest;
    }

    public AuthenticationStage getAuthenticationStage() {
        return authenticationStage;
    }

    public void setAuthenticationStage(AuthenticationStage authenticationStage) {
        this.authenticationStage = authenticationStage;
    }

    public void completeAuthentication() {
        this.authenticationStage = AuthenticationStage.COMPLETE;
    }

    @JsonIgnore
    public AuthorizationRequest getStoredRequest() {
        return getAuthorizationRequest().storedRequest();
    }

    @JsonIgnore
    public Object getUserPrincipal() {
        return getAuthorizationRequest().userAuthentication();
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        this.credentials = null;
    }
}

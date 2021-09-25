package dev.rexijie.oauth.oauth2server.token;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.api.domain.OAuth2AuthorizationRequest;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;

import java.io.Serial;
import java.util.Collection;

/**
 * Authentication that holds both the user and client authentication.
 */
public class OAuth2Authentication extends AbstractAuthenticationToken {
    @Serial
    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
    private final Object principal;
    private Object credentials;
    private OAuth2AuthorizationRequest authorizationRequest;

    public OAuth2Authentication(Object principal, Object credentials) {
        super(null);
        this.principal = principal;
        this.credentials = credentials;
    }

    /**
     * Creates a token with the supplied array of authorities.
     *
     * @param authorities the collection of <tt>GrantedAuthority</tt>s for the principal
     *                    represented by this authentication object.
     * @param credentials the credentials of the authorized client
     */
    public OAuth2Authentication(Object principal, Object credentials,
                                Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
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

    public AuthorizationRequest getStoredRequest() {
        return getAuthorizationRequest().storedRequest();
    }

    public Object getUserPrincipal() {
        return getAuthorizationRequest().authentication();
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        this.credentials = null;
    }
}

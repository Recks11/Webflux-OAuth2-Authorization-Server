package dev.rexijie.oauth.oauth2server.token;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.model.dto.ClientDTO;
import dev.rexijie.oauth.oauth2server.serializer.ApprovalTokenDeserializer;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Approval token holding the user principal, empty credentials
 * authorized client id, {@link AuthorizationRequest} and a map of approved scopes
 *
 * the approvalTokenId is id of the authorization code, that has been generated and stored.
 * Note the details in this class stores client details
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonDeserialize(using = ApprovalTokenDeserializer.class)
public class OAuth2ApprovalAuthorizationToken extends AbstractAuthenticationToken {
    private Object principal; // username of authenticated user
    private Object credentials;
    private String authorizedClientId; // authorized client id
    private String approvalTokenId; // code of the approved token
    private AuthorizationRequest authorizationRequest; // stored request
    private Map<String, Boolean> approvalMap;

    public OAuth2ApprovalAuthorizationToken() {
        super(null);
    }

    /**
     * Create OAuth2ApprovalAuthorizationToken from credentials and an AuthorizationRequest
     * @param principal the username
     * @param credentials the user password (for userAuthentication only). it can be null tbh
     * @param authorizationRequest the authorization request initiated prior to approval
     */
    public OAuth2ApprovalAuthorizationToken(Object principal, Object credentials, AuthorizationRequest authorizationRequest) {
        super(null);
        Objects.requireNonNull(authorizationRequest, "authorizationRequest can not be null");
        this.principal = principal;
        this.credentials = credentials;
        this.authorizedClientId = authorizationRequest.getClientId();
        this.authorizationRequest = authorizationRequest;
        approvalMap = new ConcurrentHashMap<>();
        authorizationRequest.getScope().forEach(scope -> approvalMap.put(scope, false));
    }

    public OAuth2ApprovalAuthorizationToken(Object principal, Object credentials, String authorizedClientId, Set<String> scopes) {
        super(null);
        this.principal = principal;
        this.credentials = credentials;
        this.authorizedClientId = authorizedClientId;
        this.approvalMap = new ConcurrentHashMap<>();
        scopes.forEach(scope -> approvalMap.put(scope, false));
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    public String getAuthorizedClientId() {
        return authorizedClientId;
    }

    public String getApprovalTokenId() {
        return approvalTokenId;
    }

    public AuthorizationRequest getAuthorizationRequest() {
        return authorizationRequest;
    }

    public void setAuthorizationRequest(AuthorizationRequest authorizationRequest) {
        this.authorizationRequest = authorizationRequest;
    }

    public Map<String, Boolean> getApprovalMap() {
        return approvalMap;
    }

    public void setApprovalTokenId(String approvalTokenId) {
        this.approvalTokenId = approvalTokenId;
    }

    public boolean isApproved(String scope) {
        return approvalMap.get(scope);
    }

    public void approve(String scope) {
        approvalMap.replace(scope, true);
    }

    @Override
    public ClientDTO getDetails() {
        return (ClientDTO) super.getDetails();
    }

    @JsonIgnore
    public boolean isAllApproved() {
        for (String scope : approvalMap.keySet())
            if (!isApproved(scope)) return false;
        return true;
    }

    @JsonIgnore
    public List<String> getApprovedScopes() {
        return approvalMap.keySet()
                .stream()
                .filter(approvalMap::get)
                .collect(Collectors.toList());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        OAuth2ApprovalAuthorizationToken token = (OAuth2ApprovalAuthorizationToken) o;
        return getPrincipal().equals(token.getPrincipal()) &&
                getCredentials().equals(token.getCredentials()) &&
                getAuthorizedClientId().equals(token.getAuthorizedClientId()) &&
                getAuthorizationRequest().equals(token.getAuthorizationRequest()) &&
                getApprovalMap().equals(token.getApprovalMap());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getPrincipal(), getAuthorizedClientId(),
                getAuthorizationRequest(), getApprovalMap(),
                getDetails(), isAuthenticated());
    }
}

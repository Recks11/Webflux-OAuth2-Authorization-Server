package dev.rexijie.oauth.oauth2server.api.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

import java.util.*;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthorizationRequest {
    public static final String AUTHORIZATION_SESSION_ATTRIBUTE = "dev.rexijie.auth.AuthorizationRequest";
    private String grantType;
    private String responseType;
    private String clientId;
    private String redirectUri;
    private Set<String> scope = new HashSet<>();
    private String nonce;
    private String state;
    private String prompt;
    private String includeGrantedScopes;
    private String responseMode;
    private String codeChallenge;
    private String codeChallengeMethod;
    private Map<String, Object> attributes = new LinkedHashMap<>();

    public AuthorizationRequest() {
    }

    public AuthorizationRequest(String grantType, String responseType, String clientId, String redirectUri, String scope, String nonce, String state) {
        this.grantType = grantType;
        this.responseType = responseType;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        if (scope != null)
            this.scope = new HashSet<>(Arrays.asList(scope.split(" ")));
        this.nonce = nonce;
        this.state = state;
    }

    public AuthorizationRequest(String grantType, String responseType,
                                String clientId, String redirectUri,
                                String scope, String nonce,
                                String state, String prompt, String includeGrantedScopes,
                                String responseMode, String codeChallenge,
                                String codeChallengeMethod, Map<String, Object> attributes) {
        this(grantType, responseType, clientId, redirectUri, scope, nonce, state);
        this.prompt = prompt;
        this.includeGrantedScopes = includeGrantedScopes;
        this.responseMode = responseMode;
        this.codeChallenge = codeChallenge;
        this.codeChallengeMethod = codeChallengeMethod;
        this.attributes = attributes;
    }

    public static AuthorizationRequest from(Map<String, String> claimsMap) {
        var paramsMap = new HashMap<>(claimsMap);
        final var request = new AuthorizationRequest(
                paramsMap.remove("grant_type"),
                paramsMap.remove("response_type"),
                paramsMap.remove("client_id"),
                paramsMap.remove("redirect_uri"),
                paramsMap.remove("scope"),
                paramsMap.remove("nonce"),
                paramsMap.remove("state"),
                paramsMap.remove("prompt"),
                paramsMap.remove("include_granted_scopes"),
                paramsMap.remove("response_mode"),
                paramsMap.remove("code_challenge"),
                paramsMap.remove("code_challenge_method"),
                new LinkedHashMap<>()
        );
        request.attributes.putAll(paramsMap);
        return request;
    }

    public String getGrantType() {
        return grantType;
    }

    public String getResponseType() {
        return responseType;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public Set<String> getScope() {
        return Set.copyOf(scope);
    }

//    public void setScope(String scopes) {
//        this.scopes = new HashSet<>(Arrays.asList(scopes.split(" ")));
//    }

    public String getNonce() {
        return nonce;
    }

    public String getState() {
        return state;
    }

    public void setScope(Set<String> scope) {
        this.scope = scope;
    }

    public String getPrompt() {
        return prompt;
    }

    public String getIncludeGrantedScopes() {
        return includeGrantedScopes;
    }

    public String getResponseMode() {
        return responseMode;
    }

    public String getCodeChallenge() {
        return codeChallenge;
    }

    public String getCodeChallengeMethod() {
        return codeChallengeMethod;
    }

    public Map<String, Object> getAttributes() {
        return Map.copyOf(attributes);
    }

    @JsonIgnore
    public String getAttribute(String name) {
        return attributes.get(name).toString();
    }

    public void setAttribute(String key, Object value) {
        this.attributes.put(key, value);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthorizationRequest that = (AuthorizationRequest) o;
        return Objects.equals(grantType, that.grantType) &&
                Objects.equals(responseType, that.responseType) &&
                Objects.equals(clientId, that.clientId) &&
                Objects.equals(redirectUri, that.redirectUri) &&
                Objects.equals(scope, that.scope) &&
                Objects.equals(nonce, that.nonce) &&
                Objects.equals(state, that.state) &&
                Objects.equals(prompt, that.prompt) &&
                Objects.equals(includeGrantedScopes, that.includeGrantedScopes) &&
                Objects.equals(responseMode, that.responseMode) && Objects.equals(codeChallenge, that.codeChallenge) &&
                Objects.equals(codeChallengeMethod, that.codeChallengeMethod) && Objects.equals(attributes, that.attributes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(getGrantType(), getResponseType(),
                getClientId(), getRedirectUri(), getScope(),
                getNonce(), getState(), getPrompt(),
                getIncludeGrantedScopes(), getResponseMode(),
                getCodeChallenge(), getCodeChallengeMethod(),
                this.attributes);
    }

    @Override
    public String toString() {
        return "AuthorizationRequest {" +
                "grantType='" + grantType + '\'' +
                ", responseType='" + responseType + '\'' +
                ", clientId='" + clientId + '\'' +
                ", redirectUri='" + redirectUri + '\'' +
                ", scopes=" + scope +
                ", nonce='" + nonce + '\'' +
                ", state='" + state + '\'' +
                ", prompt='" + prompt + '\'' +
                ", includeGrantedScopes='" + includeGrantedScopes + '\'' +
                ", responseMode='" + responseMode + '\'' +
                ", codeChallenge='" + codeChallenge + '\'' +
                ", codeChallengeMethod='" + codeChallengeMethod + '\'' +
                ", attributes=" + attributes +
                '}';
    }
}

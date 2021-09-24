package dev.rexijie.oauth.oauth2server.api.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

import java.util.*;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthorizationRequest {
    private String grantType;
    private String responseType;
    private String clientId;
    private String redirectUri;
    private Set<String> scopes;
    private String nonce;
    private String state;
    private String prompt;
    private String includeGrantedScopes;
    private String responseMode;
    private String code_challenge;
    private String code_challenge_method;
    private Map<String, Object> attributes = new LinkedHashMap<>();

    public AuthorizationRequest() {
    }

    public AuthorizationRequest(String grantType, String responseType, String clientId, String redirectUri, String scopes, String nonce, String state) {
        this.grantType = grantType;
        this.responseType = responseType;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.scopes = new HashSet<>(Arrays.asList(scopes.split(" ")));
        this.nonce = nonce;
        this.state = state;
    }

    public AuthorizationRequest(String grantType, String responseType,
                                String clientId, String redirectUri,
                                String scopes, String nonce,
                                String state, String prompt, String includeGrantedScopes,
                                String responseMode, String code_challenge,
                                String code_challenge_method, Map<String, Object> attributes) {
        this(grantType, responseType, clientId, redirectUri, scopes, nonce, state);
        this.prompt = prompt;
        this.includeGrantedScopes = includeGrantedScopes;
        this.responseMode = responseMode;
        this.code_challenge = code_challenge;
        this.code_challenge_method = code_challenge_method;
        this.attributes = attributes;
    }

    public static AuthorizationRequest from(Map<String, Object> paramsMap) {
        final var request = new AuthorizationRequest(
                paramsMap.getOrDefault("clientId", paramsMap.get("client_id")).toString(),
                paramsMap.getOrDefault("responseType", paramsMap.get("response_type")).toString(),
                paramsMap.getOrDefault("grantType", paramsMap.get("grant_type")).toString(),
                paramsMap.getOrDefault("redirectUri", paramsMap.get("redirect_uri")).toString(),
                paramsMap.remove("scopes").toString(),
                paramsMap.remove("nonce").toString(),
                paramsMap.remove("state").toString()
        );
        request.attributes = new LinkedHashMap<>();
        return request;
    }

    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }

    public String getResponseType() {
        return responseType;
    }

    public void setResponseType(String responseType) {
        this.responseType = responseType;
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

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public void setScope(String scopes) {
        this.scopes = new HashSet<>(Arrays.asList(scopes.split(" ")));
        ;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public void setScopes(Set<String> scopes) {
        this.scopes = scopes;
    }

    public String getPrompt() {
        return prompt;
    }

    public void setPrompt(String prompt) {
        this.prompt = prompt;
    }

    public String getIncludeGrantedScopes() {
        return includeGrantedScopes;
    }

    public void setIncludeGrantedScopes(String includeGrantedScopes) {
        this.includeGrantedScopes = includeGrantedScopes;
    }

    public String getResponseMode() {
        return responseMode;
    }

    public void setResponseMode(String responseMode) {
        this.responseMode = responseMode;
    }

    public String getCode_challenge() {
        return code_challenge;
    }

    public void setCode_challenge(String code_challenge) {
        this.code_challenge = code_challenge;
    }

    public String getCode_challenge_method() {
        return code_challenge_method;
    }

    public void setCode_challenge_method(String code_challenge_method) {
        this.code_challenge_method = code_challenge_method;
    }

    public Map<String, Object> getAttributes() {
        return attributes;
    }

    public void setAttributes(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthorizationRequest that = (AuthorizationRequest) o;
        return getGrantType().equals(that.getGrantType()) &&
                getResponseType().equals(that.getResponseType()) && getClientId().equals(that.getClientId())
                && Objects.equals(getRedirectUri(), that.getRedirectUri()) && getScopes().equals(that.getScopes())
                && Objects.equals(getNonce(), that.getNonce()) && Objects.equals(getState(), that.getState())
                && Objects.equals(getPrompt(), that.getPrompt()) && Objects.equals(getIncludeGrantedScopes(),
                that.getIncludeGrantedScopes()) && Objects.equals(getResponseMode(), that.getResponseMode()) &&
                Objects.equals(getCode_challenge(), that.getCode_challenge()) && Objects.equals(getCode_challenge_method(),
                that.getCode_challenge_method()) && Objects.equals(getAttributes(), that.getAttributes());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getGrantType(), getResponseType(),
                getClientId(), getRedirectUri(), getScopes(),
                getNonce(), getState(), getPrompt(),
                getIncludeGrantedScopes(), getResponseMode(),
                getCode_challenge(), getCode_challenge_method(),
                getAttributes());
    }
}

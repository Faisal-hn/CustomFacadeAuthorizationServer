package com.example.model;

public class AuthorizationCodeResponse {
    private String code;
    private String redirectUri;
    private String state;
    private String scope;
    private String error;

    // Success constructor
    public AuthorizationCodeResponse(String code, String redirectUri, String state, String scope) {
        this.code = code;
        this.redirectUri = redirectUri;
        this.state = state;
        this.scope = scope;
        this.error = null;
    }

    // Error constructor
    public AuthorizationCodeResponse(String error, String errorDescription) {
        this.code = null;
        this.redirectUri = null;
        this.state = null;
        this.scope = errorDescription; // Reusing scope field for error description
        this.error = error;
    }

    // Getters and setters
    public String getCode() { return code; }
    public void setCode(String code) { this.code = code; }
    
    public String getRedirectUri() { return redirectUri; }
    public void setRedirectUri(String redirectUri) { this.redirectUri = redirectUri; }
    
    public String getState() { return state; }
    public void setState(String state) { this.state = state; }
    
    public String getScope() { return scope; }
    public void setScope(String scope) { this.scope = scope; }
    
    public String getError() { return error; }
    public void setError(String error) { this.error = error; }

    public boolean isSuccess() {
        return error == null;
    }
} 
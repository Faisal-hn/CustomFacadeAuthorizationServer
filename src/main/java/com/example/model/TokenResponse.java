package com.example.model;

import java.util.Set;

public class TokenResponse {
    private final String accessToken;
    private final String tokenType;
    private final java.time.Instant expiresAt;
    private final String refreshToken;
    private final Set<String> scopes;
    private final String error;
    private final String errorDescription;

    // Success constructor
    public TokenResponse(String accessToken, String tokenType, java.time.Instant expiresAt, String refreshToken, Set<String> scopes) {
        this.accessToken = accessToken;
        this.tokenType = tokenType;
        this.expiresAt = expiresAt;
        this.refreshToken = refreshToken;
        this.scopes = scopes;
        this.error = null;
        this.errorDescription = null;
    }

    // Error constructor
    public TokenResponse(String error, String errorDescription) {
        this.accessToken = null;
        this.tokenType = null;
        this.expiresAt = null;
        this.refreshToken = null;
        this.scopes = null;
        this.error = error;
        this.errorDescription = errorDescription;
    }

    // Getters
    public String getAccessToken() { return accessToken; }
    public String getTokenType() { return tokenType; }
    public java.time.Instant getExpiresAt() { return expiresAt; }
    public String getRefreshToken() { return refreshToken; }
    public Set<String> getScopes() { return scopes; }
    public String getError() { return error; }
    public String getErrorDescription() { return errorDescription; }

    public boolean isSuccess() {
        return error == null;
    }
} 
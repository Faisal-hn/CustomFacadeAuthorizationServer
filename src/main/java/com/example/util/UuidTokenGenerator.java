package com.example.util;

import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.time.Instant;
import java.util.UUID;

public class UuidTokenGenerator implements OAuth2TokenGenerator<OAuth2Token> {
    @Override
    public OAuth2Token generate(OAuth2TokenContext context) {
        String tokenType = context.getTokenType() != null ? context.getTokenType().getValue() : null;
        if ("access_token".equals(tokenType)) {
            String tokenValue = UUID.randomUUID().toString();
            Instant issuedAt = Instant.now();
            Instant expiresAt = issuedAt.plusSeconds(300); // 5 minutes
            return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, tokenValue, issuedAt, expiresAt, context.getAuthorizedScopes());
        } else if ("refresh_token".equals(tokenType)) {
            String tokenValue = UUID.randomUUID().toString();
            Instant issuedAt = Instant.now();
            Instant expiresAt = issuedAt.plusSeconds(3600); // 1 hour
            return new OAuth2RefreshToken(tokenValue, issuedAt, expiresAt);
        }
        return null;
    }
} 
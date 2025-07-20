package com.example.facade;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.example.model.TokenResponse;

import java.util.Set;

@Service
public class CompleteOAuth2FacadeService {
    private final AuthorizationCodeFacadeService authorizationCodeFacadeService;
    private final TokenGenerationFacadeService tokenGenerationFacadeService;

    @Autowired
    public CompleteOAuth2FacadeService(
            AuthorizationCodeFacadeService authorizationCodeFacadeService,
            TokenGenerationFacadeService tokenGenerationFacadeService
    ) {
        this.authorizationCodeFacadeService = authorizationCodeFacadeService;
        this.tokenGenerationFacadeService = tokenGenerationFacadeService;
    }

    public TokenResponse performCompleteOAuth2Flow(
            String username, 
            String password, 
            String clientId, 
            String clientSecret, 
            String redirectUri, 
            Set<String> scopes
    ) {
        // Step 1: Generate authorization code
        String authorizationCode = authorizationCodeFacadeService.generateAuthorizationCode(
                username, password, clientId, redirectUri, scopes
        );

        // Step 2: Exchange authorization code for tokens
        TokenResponse tokenResponse = tokenGenerationFacadeService.exchangeAuthorizationCodeForToken(
                authorizationCode, clientId, clientSecret, redirectUri
        );

        return tokenResponse;
    }

    public TokenResponse performCompleteOAuth2Flow(
            String username, 
            String password, 
            String clientId, 
            String clientSecret, 
            String redirectUri, 
            String scope
    ) {
        Set<String> scopes = Set.of(scope);
        return performCompleteOAuth2Flow(username, password, clientId, clientSecret, redirectUri, scopes);
    }
} 
package com.example.facade;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import java.util.HashMap;
import com.example.model.TokenResponse;

@Service
public class TokenGenerationFacadeService {
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final AuthorizationServerSettings authorizationServerSettings;
    private final OAuth2TokenGenerator<OAuth2Token> tokenGenerator;

    @Autowired
    public TokenGenerationFacadeService(
            RegisteredClientRepository registeredClientRepository,
            OAuth2AuthorizationService authorizationService,
            AuthorizationServerSettings authorizationServerSettings,
            OAuth2TokenGenerator<OAuth2Token> tokenGenerator
    ) {
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationService = authorizationService;
        this.authorizationServerSettings = authorizationServerSettings;
        this.tokenGenerator = tokenGenerator;
    }

    public TokenResponse exchangeAuthorizationCodeForToken(String authorizationCode, String clientId, String clientSecret, String redirectUri) {
        // 1. Validate and load client
        RegisteredClient registeredClient = validateAndLoadClient(clientId, clientSecret);

        // 2. Set up authorization server context
        AuthorizationServerContext context = createAuthorizationServerContext();
        AuthorizationServerContextHolder.setContext(context);

        try {
            // 3. Create client authentication
            OAuth2ClientAuthenticationToken clientAuth = createClientAuthentication(registeredClient);

            // 4. Build and process authorization code request
            OAuth2AuthorizationCodeAuthenticationToken authRequest = 
                    new OAuth2AuthorizationCodeAuthenticationToken(authorizationCode, clientAuth, redirectUri, new HashMap<>());

            // 5. Authenticate and get tokens
            OAuth2AccessTokenAuthenticationToken result = authenticateAndGetTokens(authRequest);

            // 6. Extract and return tokens
            return extractTokenResponse(result);
        } finally {
            AuthorizationServerContextHolder.resetContext();
        }
    }

    private RegisteredClient validateAndLoadClient(String clientId, String clientSecret) {
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw new IllegalArgumentException("Client not found: " + clientId);
        }

        if (!clientSecret.equals(registeredClient.getClientSecret())) {
            throw new IllegalArgumentException("Invalid client secret");
        }

        return registeredClient;
    }

    private AuthorizationServerContext createAuthorizationServerContext() {
        return new AuthorizationServerContext() {
            @Override
            public String getIssuer() {
                return "http://localhost:8081";
            }

            @Override
            public AuthorizationServerSettings getAuthorizationServerSettings() {
                return authorizationServerSettings;
            }
        };
    }

    private OAuth2ClientAuthenticationToken createClientAuthentication(RegisteredClient registeredClient) {
        return new OAuth2ClientAuthenticationToken(
                registeredClient, 
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, 
                null
        );
    }

    private OAuth2AccessTokenAuthenticationToken authenticateAndGetTokens(OAuth2AuthorizationCodeAuthenticationToken authRequest) {
        OAuth2AuthorizationCodeAuthenticationProvider provider = 
                new OAuth2AuthorizationCodeAuthenticationProvider(authorizationService, tokenGenerator);
        
        return (OAuth2AccessTokenAuthenticationToken) provider.authenticate(authRequest);
    }

    private TokenResponse extractTokenResponse(OAuth2AccessTokenAuthenticationToken result) {
        OAuth2AccessToken accessToken = result.getAccessToken();
        OAuth2RefreshToken refreshToken = result.getRefreshToken();

        return new TokenResponse(
                accessToken.getTokenValue(),
                accessToken.getTokenType().getValue(),
                accessToken.getExpiresAt(),
                refreshToken != null ? refreshToken.getTokenValue() : null,
                null
        );
    }


} 
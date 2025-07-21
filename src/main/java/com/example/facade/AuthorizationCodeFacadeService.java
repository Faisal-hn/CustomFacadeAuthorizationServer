package com.example.facade;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

import java.util.Set;
import java.util.HashMap;

@Service
public class AuthorizationCodeFacadeService {
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2AuthorizationConsentService consentService;
    private final AuthenticationManager authenticationManager;
    private final AuthorizationServerSettings authorizationServerSettings;

    @Autowired
    public AuthorizationCodeFacadeService(
            RegisteredClientRepository registeredClientRepository,
            AuthenticationManager authenticationManager,
            OAuth2AuthorizationService authorizationService,
            AuthorizationServerSettings authorizationServerSettings
    ) {
        this.registeredClientRepository = registeredClientRepository;
        this.authenticationManager = authenticationManager;
        this.authorizationService = authorizationService;
        this.authorizationServerSettings = authorizationServerSettings;
        this.consentService = new InMemoryOAuth2AuthorizationConsentService();
    }

    public String generateAuthorizationCode(String username, String password, String clientId, String redirectUri, Set<String> scopes) {
        // 1. Authenticate user
        Authentication userAuth = authenticateUser(username, password);

        // 2. Validate and load client
        RegisteredClient registeredClient = validateAndLoadClient(clientId);

        // 3. Set up authorization server context
        AuthorizationServerContext context = createAuthorizationServerContext();
        AuthorizationServerContextHolder.setContext(context);

        try {
            // 4. Create authorization code request
            OAuth2AuthorizationCodeRequestAuthenticationToken authRequest = 
                    createAuthorizationCodeRequest(clientId, userAuth, redirectUri, scopes);

            // 5. Process authorization code request
            OAuth2AuthorizationCodeRequestAuthenticationToken result = processAuthorizationCodeRequest(authRequest);

            // 6. Extract and return authorization code
            return extractAuthorizationCode(result);
        } finally {
            AuthorizationServerContextHolder.resetContext();
        }
    }

    private Authentication authenticateUser(String username, String password) {
        Authentication userAuth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );
        SecurityContextHolder.getContext().setAuthentication(userAuth);
        return userAuth;
    }

    private RegisteredClient validateAndLoadClient(String clientId) {
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw new IllegalArgumentException("Client not found: " + clientId);
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

    private OAuth2AuthorizationCodeRequestAuthenticationToken createAuthorizationCodeRequest(
            String clientId, Authentication userAuth, String redirectUri, Set<String> scopes) {
        return new OAuth2AuthorizationCodeRequestAuthenticationToken(
                "http://localhost:8081/oauth2/authorize",
                clientId,
                userAuth,
                redirectUri,
                "state",
                scopes,
                new HashMap<>()
        );
    }

    private OAuth2AuthorizationCodeRequestAuthenticationToken processAuthorizationCodeRequest(
            OAuth2AuthorizationCodeRequestAuthenticationToken authRequest) {
        OAuth2AuthorizationCodeRequestAuthenticationProvider provider =
                new OAuth2AuthorizationCodeRequestAuthenticationProvider(
                        registeredClientRepository, authorizationService, consentService
                );
        return (OAuth2AuthorizationCodeRequestAuthenticationToken) provider.authenticate(authRequest);
    }

    private String extractAuthorizationCode(OAuth2AuthorizationCodeRequestAuthenticationToken result) {
        return result.getAuthorizationCode().getTokenValue();
    }
} 
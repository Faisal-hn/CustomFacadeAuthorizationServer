package com.example.proxy;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class AuthTokenFacade {

    @Autowired
    private OAuthServiceProxy oAuthServiceProxy;

    public String getAccessToken(String username, String clientId, String redirectUri, String scope) {
        try {
            System.out.println("[DEBUG] Facade processing request for user: " + username);
            String result = oAuthServiceProxy.getAccessToken(username, clientId, redirectUri, scope);
            System.out.println("[DEBUG] Facade got result: " + result);
            return result;
        } catch (Exception e) {
            System.out.println("[DEBUG] Facade caught exception: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }
} 
package com.example.proxy;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthTokenController {

    @Autowired
    private AuthTokenFacade authTokenFacade;

    @GetMapping(value = "/proxy/access-token", produces = MediaType.APPLICATION_JSON_VALUE)
    public String getAccessToken(
            @RequestParam String username,
            @RequestParam String clientId,
            @RequestParam String redirectUri,
            @RequestParam(required = false) String scope
    ) {
        try {
            System.out.println("[DEBUG] Controller received request for user: " + username);
            String result = authTokenFacade.getAccessToken(username, clientId, redirectUri, scope);
            System.out.println("[DEBUG] Controller returning result: " + result);
            return result;
        } catch (Exception e) {
            System.out.println("[DEBUG] Controller caught exception: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }
} 
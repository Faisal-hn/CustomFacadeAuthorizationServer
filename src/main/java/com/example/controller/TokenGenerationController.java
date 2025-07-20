package com.example.controller;

import com.example.facade.TokenGenerationFacadeService;
import com.example.model.TokenResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/sample")
public class TokenGenerationController {

    @Autowired
    private TokenGenerationFacadeService tokenGenerationFacadeService;

    @GetMapping(value = "/token", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<TokenResponse> exchangeAuthorizationCodeForToken(
            @RequestParam String authorizationCode,
            @RequestParam String clientId,
            @RequestParam String clientSecret,
            @RequestParam String redirectUri
    ) {
        try {
            TokenResponse response = tokenGenerationFacadeService.exchangeAuthorizationCodeForToken(
                    authorizationCode, clientId, clientSecret, redirectUri
            );
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new TokenResponse("error", e.getMessage()));
        }
    }
} 
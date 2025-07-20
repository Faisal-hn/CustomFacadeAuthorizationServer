package com.example.controller;

import com.example.facade.AuthorizationCodeFacadeService;
import com.example.model.AuthorizationCodeResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Set;
import java.util.Arrays;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/sample")
public class AuthorizationCodeController {

    @Autowired
    private AuthorizationCodeFacadeService authorizationCodeFacadeService;

    @GetMapping(value = "/authorize", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AuthorizationCodeResponse> generateAuthorizationCode(
            @RequestParam String username,
            @RequestParam String password,
            @RequestParam String clientId,
            @RequestParam String redirectUri,
            @RequestParam(required = false, defaultValue = "read") String scope
    ) {
        try {
            Set<String> scopes = Arrays.stream(scope.split(" "))
                    .filter(s -> !s.trim().isEmpty())
                    .collect(Collectors.toSet());
            
            String authorizationCode = authorizationCodeFacadeService.generateAuthorizationCode(
                    username, password, clientId, redirectUri, scopes
            );
            
            AuthorizationCodeResponse response = new AuthorizationCodeResponse(
                    authorizationCode, 
                    redirectUri, 
                    "state", 
                    scope
            );
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new AuthorizationCodeResponse("error", e.getMessage()));
        }
    }
} 
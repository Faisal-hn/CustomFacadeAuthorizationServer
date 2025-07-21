package com.example.facadeController;

import com.example.facade.CompleteOAuth2FacadeService;
import com.example.model.TokenResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Set;
import java.util.Arrays;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/sample")
public class CompleteOAuth2Controller {

    @Autowired
    private CompleteOAuth2FacadeService completeOAuth2FacadeService;

    @GetMapping(value = "/oauth2-flow", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<TokenResponse> performCompleteOAuth2Flow(
            @RequestParam String username,
            @RequestParam String password,
            @RequestParam String clientId,
            @RequestParam String clientSecret,
            @RequestParam String redirectUri,
            @RequestParam(required = false, defaultValue = "read") String scope
    ) {
        try {
            Set<String> scopes = Arrays.stream(scope.split(" "))
                    .filter(s -> !s.trim().isEmpty())
                    .collect(Collectors.toSet());
            
            TokenResponse response = completeOAuth2FacadeService.performCompleteOAuth2Flow(
                    username, password, clientId, clientSecret, redirectUri, scopes
            );
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new TokenResponse("error", e.getMessage()));
        }
    }
}
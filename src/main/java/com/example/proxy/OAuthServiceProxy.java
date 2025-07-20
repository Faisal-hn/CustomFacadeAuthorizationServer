package com.example.proxy;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.net.HttpURLConnection;
import java.io.IOException;

@Service
public class OAuthServiceProxy {

    @Value("${proxy.auth-server-base-url:http://localhost:8081}")
    private String authServerBaseUrl;

    private final RestTemplate restTemplate = new RestTemplate();

    public OAuthServiceProxy() {
        // Prevent RestTemplate from following redirects
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory() {
            @Override
            protected void prepareConnection(HttpURLConnection connection, String httpMethod) throws IOException {
                super.prepareConnection(connection, httpMethod);
                connection.setInstanceFollowRedirects(false);
            }
        };
        this.restTemplate.setRequestFactory(requestFactory);
    }

    public String getAuthorizationCode(String username, String clientId, String redirectUri, String scope) {
        // Build /oauth2/authorize URL
        UriComponentsBuilder builder = UriComponentsBuilder
                .fromHttpUrl(authServerBaseUrl + "/oauth2/authorize")
                .queryParam("response_type", "code")
                .queryParam("client_id", clientId)
                .queryParam("redirect_uri", redirectUri);
        if (scope != null) builder.queryParam("scope", scope);

        URI uri = builder.build().toUri();

        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Auth-User", username);
        HttpEntity<?> entity = new HttpEntity<>(headers);

        ResponseEntity<String> response = restTemplate.exchange(uri, HttpMethod.GET, entity, String.class);
        if (response.getStatusCode().is3xxRedirection()) {
            URI location = response.getHeaders().getLocation();
            if (location != null) {
                String code = UriComponentsBuilder.fromUri(location).build().getQueryParams().getFirst("code");
                return code;
            }
        }
        throw new RuntimeException("Failed to get authorization code");
    }

    public String getAccessToken(String username, String clientId, String redirectUri, String scope) {
        try {
            System.out.println("[DEBUG] Getting authorization code for user: " + username);
            String code = getAuthorizationCode(username, clientId, redirectUri, scope);
            System.out.println("[DEBUG] Got authorization code: " + code);

            HttpHeaders headers = new HttpHeaders();
            headers.set("X-Auth-User", username);
            headers.setBasicAuth(clientId, "client"); // Use the actual client secret if not "client"
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "authorization_code");
            body.add("code", code);
            body.add("redirect_uri", redirectUri);
            if (scope != null) body.add("scope", scope);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

            System.out.println("[DEBUG] Making token request to: " + authServerBaseUrl + "/oauth2/token");
            ResponseEntity<String> response = restTemplate.postForEntity(
                authServerBaseUrl + "/oauth2/token",
                request,
                String.class
            );
            System.out.println("[DEBUG] Token response status: " + response.getStatusCode());
            System.out.println("[DEBUG] Token response body: " + response.getBody());
            return response.getBody();
        } catch (Exception e) {
            System.out.println("[DEBUG] Error getting access token: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }
} 
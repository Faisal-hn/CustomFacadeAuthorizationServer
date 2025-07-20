```bash
mysql -u root -proot -e "SELECT * FROM oauthdb.oauth2_authorization WHERE id='177a6c99-7aaf-4298-930a-438fce57e796'\G" | cat
```
Here is the **full entry** for authorization with all token values included (for testing):

```json
{
  "id": "177a6c99-7aaf-4298-930a-438fce57e796",
  "registered_client_id": "c0b2fa18-7766-493d-97d5-52bd7725207f",
  "principal_name": "bill",
  "authorization_grant_type": "authorization_code",
  "authorized_scopes": "read",
  "attributes": {
    "@class": "java.util.Collections$UnmodifiableMap",
    "org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest": {
      "@class": "org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest",
      "authorizationUri": "http://localhost:8081/oauth2/authorize",
      "authorizationGrantType": { "value": "authorization_code" },
      "responseType": { "value": "code" },
      "clientId": "client",
      "redirectUri": "http://localhost:9000/authorized",
      "scopes": ["java.util.Collections$UnmodifiableSet", ["read"]],
      "state": null,
      "additionalParameters": {
        "@class": "java.util.Collections$UnmodifiableMap",
        "continue": ""
      },
      "authorizationRequestUri": "http://localhost:8081/oauth2/authorize?response_type=code&client_id=client&scope=read&redirect_uri=http://localhost:9000/authorized&continue=",
      "attributes": { "@class": "java.util.Collections$UnmodifiableMap" }
    },
    "java.security.Principal": {
      "@class": "org.springframework.security.authentication.UsernamePasswordAuthenticationToken",
      "authorities": [
        "java.util.Collections$UnmodifiableRandomAccessList",
        [
          { "@class": "org.springframework.security.core.authority.SimpleGrantedAuthority", "authority": "ROLE_USER" }
        ]
      ],
      "details": {
        "@class": "org.springframework.security.web.authentication.WebAuthenticationDetails",
        "remoteAddress": "0:0:0:0:0:0:0:1",
        "sessionId": "6E24080FEEAA43D8522CA0849FC5F0C4"
      },
      "authenticated": true,
      "principal": {
        "@class": "org.springframework.security.core.userdetails.User",
        "password": null,
        "username": "bill",
        "authorities": [
          "java.util.Collections$UnmodifiableSet",
          [
            { "@class": "org.springframework.security.core.authority.SimpleGrantedAuthority", "authority": "ROLE_USER" }
          ]
        ],
        "accountNonExpired": true,
        "accountNonLocked": true,
        "credentialsNonExpired": true,
        "enabled": true
      },
      "credentials": null
    }
  },
  "state": null,
  "authorization_code_value": "e4tbS-aWyJ6_Szb22M7DdC3_sYxViwQtBN15pDkJqjzM865B_X7udwBzsHrmF5sArrdhIIs8hRAD541th3kAROr83o1LXKJ8JnXi0wxzGsCHmQsvd5PnKv1BDTUZF24b",
  "authorization_code_issued_at": "2025-07-16 14:40:07",
  "authorization_code_expires_at": "2025-07-16 14:45:07",
  "authorization_code_metadata": {
    "@class": "java.util.Collections$UnmodifiableMap",
    "metadata.token.invalidated": true
  },
  "access_token_value": "dFaOntuLi_kbPWmccWYvRYKQN-CV9oxy5vVCXwTfIY-15zxiTtvS47hwmUjGY3rly13WheXhGUM4u1kYJHRxdiO_P9OJFejOsq8dwIE9vxS7rp8Uv4BrvPtrF-3-n0ms",
  "access_token_issued_at": "2025-07-16 14:41:05",
  "access_token_expires_at": "2025-07-16 14:46:05",
  "access_token_metadata": {
    "@class": "java.util.Collections$UnmodifiableMap",
    "metadata.token.claims": {
      "@class": "java.util.Collections$UnmodifiableMap",
      "sub": "bill",
      "aud": ["java.util.Collections$SingletonList", ["client"]],
      "nbf": ["java.time.Instant", 1752657065.002874238],
      "scope": ["java.util.Collections$UnmodifiableSet", ["read"]],
      "iss": ["java.net.URL", "http://localhost:8081"],
      "exp": ["java.time.Instant", 1752657365.002874238],
      "iat": ["java.time.Instant", 1752657065.002874238],
      "jti": "d124120f-2cb4-43b7-89fd-7b59ad3ca493"
    },
    "metadata.token.invalidated": false
  },
  "access_token_type": "Bearer",
  "access_token_scopes": "read",
  "oidc_id_token_value": null,
  "oidc_id_token_issued_at": null,
  "oidc_id_token_expires_at": null,
  "oidc_id_token_metadata": null,
  "refresh_token_value": "16eEKKc5GQ9qIdsYGqmT3BSlxORYL53wTOVU5I6s0AmC_wMP5LxIEmOMgpXI03UraifVM9_jKuPH7PnYMeqmONufhVQW7FC-DV0vdg6Q2sozU-aLwyRNQnnEom05uKli",
  "refresh_token_issued_at": "2025-07-16 14:41:05",
  "refresh_token_expires_at": "2025-07-16 15:41:05",
  "refresh_token_metadata": {
    "@class": "java.util.Collections$UnmodifiableMap",
    "metadata.token.invalidated": false
  },
  "created_at": "2025-07-16 14:40:07",
  "user_code_value": null,
  "user_code_issued_at": null,
  "user_code_expires_at": null,
  "user_code_metadata": null,
  "device_code_value": null,
  "device_code_issued_at": null,
  "device_code_expires_at": null,
  "device_code_metadata": null
}
```

package com.example.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import java.time.Duration;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import javax.sql.DataSource;
import com.example.JpaUserDetailsService;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import com.example.config.UuidTokenGenerator;
import com.example.proxy.StatelessUserAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.http.MediaType;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Configuration
public class SecurityConfig {

  // @Bean
  // @Order(1)
  // public SecurityFilterChain asFilterChain(HttpSecurity http)
  //     throws Exception {
  //   OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

  //   http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
  //       .oidc(Customizer.withDefaults());

  //   http.exceptionHandling((e) ->
  //           e.authenticationEntryPoint(
  //               new LoginUrlAuthenticationEntryPoint("/login"))
  //       );

  //   // Add stateless user authentication filter before SecurityContextHolderFilter and set session management to stateless
  //   http
  //       // .addFilterAfter(new com.example.proxy.StatelessUserAuthenticationFilter(), SecurityContextHolderFilter.class)
  //       .addFilterAfter(new com.example.proxy.StatelessUserAuthenticationFilter(), LogoutFilter.class)
  //       .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
  //       .csrf(csrf -> csrf.disable())
  //       .formLogin(form -> form.disable())
  //       .httpBasic(basic -> basic.disable())
  //       .logout(logout -> logout.disable())
  //       .rememberMe(remember -> remember.disable())
  //       .anonymous(anonymous -> anonymous.disable())
  //       .requestCache(cache -> cache.disable());

  //   return http.build();
  // }

  @Bean 
	@Order(1)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
			throws Exception {
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
				OAuth2AuthorizationServerConfigurer.authorizationServer();

		http
			.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
			.with(authorizationServerConfigurer, (authorizationServer) ->
				authorizationServer
					.oidc(Customizer.withDefaults())	// Enable OpenID Connect 1.0
			)
			.addFilterAfter(new StatelessUserAuthenticationFilter(), LogoutFilter.class).csrf(csrf -> csrf.disable())
			// Redirect to the login page when not authenticated from the
			// authorization endpoint
			.exceptionHandling((exceptions) -> exceptions
				.defaultAuthenticationEntryPointFor(
					new LoginUrlAuthenticationEntryPoint("/login"),
					new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
				)
			);

		return http.build();
	}

  @Bean
  @Order(2)
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
      throws Exception {
        // permit all requests

    http.formLogin(Customizer.withDefaults());

    http.authorizeHttpRequests(
      //  c -> c.anyRequest().permitAll()
      c -> c.requestMatchers("/proxy/**").permitAll()
      .anyRequest().authenticated()
    );
    return http.build();
  }

  @Bean
  public UserDetailsService userDetailsService(JpaUserDetailsService jpaUserDetailsService) {
    return jpaUserDetailsService;
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return NoOpPasswordEncoder.getInstance();
  }

  @Bean
  public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
    return new JdbcRegisteredClientRepository(jdbcTemplate);
  }

  @Bean
  public AuthenticationProvider authenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
    DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
    authProvider.setUserDetailsService(userDetailsService);
    authProvider.setPasswordEncoder(passwordEncoder);
    return authProvider;
  }

  @Bean
  public AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder().build();
  }

  @Bean
  public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
    return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
  }

  @Bean
  public OAuth2TokenGenerator<OAuth2Token> tokenGenerator() {
    return new UuidTokenGenerator();
  }

  // @Bean
  // public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
  //   KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
  //   keyPairGenerator.initialize(2048);
  //   KeyPair keyPair = keyPairGenerator.generateKeyPair();

  //   RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
  //   RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
  //   RSAKey rsaKey = new RSAKey.Builder(publicKey)
  //       .privateKey(privateKey)
  //       .keyID(UUID.randomUUID().toString())
  //       .build();
  //   JWKSet jwkSet = new JWKSet(rsaKey);
  //   return new ImmutableJWKSet<>(jwkSet);
  // }

  // @Bean
  // public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
  //   return context -> {
  //     JwtClaimsSet.Builder claims = context.getClaims();
  //     claims.claim("priority", "HIGH");
  //   };
  // }
}

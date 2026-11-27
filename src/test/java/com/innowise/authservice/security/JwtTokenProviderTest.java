package com.innowise.authservice.security;

import com.innowise.authservice.entity.Role;
import com.innowise.authservice.entity.Credential;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

class
JwtTokenProviderTest {

    private JwtTokenProvider provider;
    private Credential credential;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        String privateB64 = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        String publicB64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());

        provider = new JwtTokenProvider(privateB64, publicB64, 900_000, 604_800_000);

        credential = new Credential();
        credential.setUsername("test@example.com");
        credential.setUserId(1L);
        credential.setRole(Role.USER);
    }

    @Test
    void generateAccessToken_shouldContainClaims() {
        String token = provider.generateAccessToken(credential);
        Claims claims = provider.parseClaims(token);

        assertThat(claims.getSubject()).isEqualTo("test@example.com");
        assertThat(claims.get("userId", Integer.class)).isEqualTo(1);
        assertThat(claims.get("role", String.class)).isEqualTo("USER");
        assertThat(claims.get("type", String.class)).isEqualTo("access");
    }

    @Test
    void generateRefreshToken_shouldHaveRefreshType() {
        String token = provider.generateRefreshToken(credential);
        Claims claims = provider.parseClaims(token);

        assertThat(claims.get("type", String.class)).isEqualTo("refresh");
    }

    @Test
    void validateToken_shouldReturnTrueForValidToken() {
        String token = provider.generateAccessToken(credential);
        assertThat(provider.validateToken(token)).isTrue();
    }

    @Test
    void validateToken_shouldReturnFalseForInvalidToken() {
        assertThat(provider.validateToken("invalid.token.here")).isFalse();
    }

    @Test
    void validateToken_shouldReturnFalseForExpiredToken() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        String privateB64 = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        String publicB64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());

        JwtTokenProvider shortLived = new JwtTokenProvider(privateB64, publicB64, 1, 1);
        String token = shortLived.generateAccessToken(credential);

        Thread.sleep(50);
        assertThat(shortLived.validateToken(token)).isFalse();
    }
}

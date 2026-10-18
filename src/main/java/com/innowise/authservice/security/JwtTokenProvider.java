package com.innowise.authservice.security;

import com.innowise.authservice.entity.UserCredential;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtTokenProvider {
    private final SecretKey key;
    private final long accessExp;
    private final long refreshExp;

    public JwtTokenProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.access-expiration-ms}") long accessExp,
            @Value("${jwt.refresh-expiration-ms}") long refreshExp) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessExp = accessExp;
        this.refreshExp = refreshExp;
    }

    public String generateAccessToken(UserCredential credential) {
        return buildToken(credential, accessExp);
    }

    public String generateRefreshToken(UserCredential credential) {
        return buildToken(credential, refreshExp);
    }

    private String buildToken(UserCredential credential, long expiration) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expiration);
        return Jwts.builder()
                .subject(credential.getLogin())
                .claim("userId", credential.getUserId())
                .claim("role", credential.getRole().name())
                .issuedAt(now)
                .expiration(expiry)
                .signWith(key)
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public Claims parseClaims(String token) {
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();
    }

}

package com.innowise.authservice.security;

import com.innowise.authservice.entity.Credential;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtTokenProvider {
    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;
    private final long accessExp;
    private final long refreshExp;

    public JwtTokenProvider(
            @Value("${jwt.private-key}") String privateKeyB64,
            @Value("${jwt.public-key}") String publicKeyB64,
            @Value("${jwt.access-expiration-ms}") long accessExp,
            @Value("${jwt.refresh-expiration-ms}") long refreshExp) throws Exception {
        this.privateKey = parsePrivateKey(privateKeyB64);
        this.publicKey = parsePublicKey(publicKeyB64);
        this.accessExp = accessExp;
        this.refreshExp = refreshExp;
    }

    public String generateAccessToken(Credential credential) {
        return buildToken(credential, accessExp, "access");
    }

    public String generateRefreshToken(Credential credential) {
        return buildToken(credential, refreshExp, "refresh");
    }

    private String buildToken(Credential credential, long expiration, String type) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expiration);
        return Jwts.builder()
                .subject(credential.getUsername())
                .claim("user_id", credential.getUserId())
                .claim("role", credential.getRole().name())
                .claim("type", type)
                .header().keyId("auth-key-1").and()
                .issuedAt(now)
                .expiration(expiry)
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().verifyWith(publicKey).build().parseSignedClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public Claims parseClaims(String token) {
        return Jwts.parser().verifyWith(publicKey).build().parseSignedClaims(token).getPayload();
    }

    public RSAPublicKey getPublicKey() { return publicKey; }

    private RSAPrivateKey parsePrivateKey(String base64) throws Exception {
        String cleaned = base64.replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(cleaned);
        return (RSAPrivateKey) KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(decoded));
    }

    private RSAPublicKey parsePublicKey(String base64) throws Exception {
        String cleaned = base64.replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(cleaned);
        return (RSAPublicKey) KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(decoded));
    }
}
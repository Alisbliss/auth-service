package com.innowise.authservice.controller;

import com.innowise.authservice.security.JwtTokenProvider;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.jwk.RSAKey;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class JwksController {
    private final JwtTokenProvider provider;

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> jwks() {
        RSAKey rsaKey = new RSAKey.Builder(provider.getPublicKey())
                .keyID("auth-key-1")
                .algorithm(JWSAlgorithm.RS256)
                .build();
        return new JWKSet(rsaKey).toJSONObject();
    }
}

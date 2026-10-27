package com.innowise.authservice.service;

import com.innowise.authservice.dto.LoginRequest;
import com.innowise.authservice.dto.RegisterRequest;
import com.innowise.authservice.dto.TokenResponse;
import com.innowise.authservice.entity.UserCredential;
import com.innowise.authservice.exception.ConflictException;
import com.innowise.authservice.exception.UnauthorizedException;
import com.innowise.authservice.repository.UserCredentialRepository;
import com.innowise.authservice.security.JwtTokenProvider;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserCredentialRepository credentialRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    public void register(RegisterRequest request) {
        if (credentialRepository.existsByLogin(request.getLogin())) {
            throw new ConflictException("Login already exists: " + request.getLogin());
        }
        UserCredential credential = new UserCredential();
        credential.setLogin(request.getLogin());
        credential.setPassword(passwordEncoder.encode(request.getPassword()));
        credential.setRole(request.getRole());
        credential.setUserId(request.getUserId());
        credentialRepository.save(credential);
    }

    public TokenResponse refresh(String refreshToken) {
        if (!jwtTokenProvider.validateToken(refreshToken)) {
            throw new UnauthorizedException("Invalid refresh token");
        }
        Claims claims = jwtTokenProvider.parseClaims(refreshToken);
        String login = claims.getSubject();

        UserCredential credential = credentialRepository.findByLogin(login)
                .orElseThrow(() -> new UnauthorizedException("User not found: " + login));

        return TokenResponse.builder()
                .accessToken(jwtTokenProvider.generateAccessToken(credential))
                .refreshToken(jwtTokenProvider.generateRefreshToken(credential))
                .build();
    }

    public boolean validate(String token) {
        return jwtTokenProvider.validateToken(token);
    }

    public TokenResponse login(LoginRequest request) {
        UserCredential credential = credentialRepository.findByLogin(request.getLogin())
                .orElseThrow(() -> new BadCredentialsException("Invalid login or password"));

        if (!passwordEncoder.matches(request.getPassword(), credential.getPassword())) {
            throw new BadCredentialsException("Invalid login or password");}

        return TokenResponse.builder()
                .accessToken(jwtTokenProvider.generateAccessToken(credential))
                .refreshToken(jwtTokenProvider.generateRefreshToken(credential))
                .build();
    }
}

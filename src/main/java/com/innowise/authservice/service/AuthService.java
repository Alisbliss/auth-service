package com.innowise.authservice.service;

import com.innowise.authservice.client.UserClient;
import com.innowise.authservice.dto.LoginRequest;
import com.innowise.authservice.dto.RegisterRequest;
import com.innowise.authservice.dto.TokenResponse;
import com.innowise.authservice.dto.UserCreateRequest;
import com.innowise.authservice.dto.UserResponse;
import com.innowise.authservice.entity.Credential;
import com.innowise.authservice.exception.ConflictException;
import com.innowise.authservice.exception.UnauthorizedException;
import com.innowise.authservice.mapper.CredentialMapper;
import com.innowise.authservice.repository.CredentialRepository;
import com.innowise.authservice.security.JwtTokenProvider;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {
    private final CredentialRepository credentialRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserClient userClient;
    private final CredentialMapper credentialMapper;

    @Transactional
    public void register(RegisterRequest request) {
        if (credentialRepository.existsByUsername(request.getLogin())) {
            throw new ConflictException("Login already exists: " + request.getLogin());
        }

        UserResponse user = userClient.createUser(UserCreateRequest.builder()
                .name(request.getName())
                .surname(request.getSurname())
                .birthDate(request.getBirthDate())
                .email(request.getEmail())
                .active(true)
                .build());

        try {
            Credential credential = credentialMapper.toEntity(request, user.getId());
            credential.setPasswordHash(passwordEncoder.encode(request.getPassword()));
            credentialRepository.save(credential);
        } catch (Exception e) {
            try {
                userClient.deleteUser(user.getId());
            } catch (Exception rollbackErr) {
                log.error("Rollback failed for user {}", user.getId(), rollbackErr);
            }
            throw new RuntimeException("Registration failed", e);
        }
    }

    public TokenResponse refresh(String refreshToken) {
        if (!jwtTokenProvider.validateToken(refreshToken)) {
            throw new UnauthorizedException("Invalid refresh token");
        }
        Claims claims = jwtTokenProvider.parseClaims(refreshToken);
        if (!"refresh".equals(claims.get("type", String.class))) {
            throw new UnauthorizedException("Not a refresh token");
        }
        String login = claims.getSubject();

        Credential credential = credentialRepository.findByUsername(login)
                .orElseThrow(() -> new UnauthorizedException("User not found: " + login));

        return TokenResponse.builder()
                .accessToken(jwtTokenProvider.generateAccessToken(credential))
                .refreshToken(jwtTokenProvider.generateRefreshToken(credential))
                .build();
    }

    public TokenResponse login(LoginRequest request) {
        Credential credential = credentialRepository.findByUsername(request.getLogin())
                .orElseThrow(() -> new BadCredentialsException("Invalid login or password"));

        if (!passwordEncoder.matches(request.getPassword(), credential.getPasswordHash())) {
            throw new BadCredentialsException("Invalid login or password");}

        return TokenResponse.builder()
                .accessToken(jwtTokenProvider.generateAccessToken(credential))
                .refreshToken(jwtTokenProvider.generateRefreshToken(credential))
                .build();
    }
}

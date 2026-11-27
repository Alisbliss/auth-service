package com.innowise.authservice.service;

import com.innowise.authservice.client.UserClient;
import com.innowise.authservice.dto.LoginRequest;
import com.innowise.authservice.dto.RegisterRequest;
import com.innowise.authservice.dto.TokenResponse;
import com.innowise.authservice.dto.UserResponse;
import com.innowise.authservice.entity.Role;
import com.innowise.authservice.entity.Credential;
import com.innowise.authservice.exception.ConflictException;
import com.innowise.authservice.exception.UnauthorizedException;
import com.innowise.authservice.mapper.CredentialMapper;
import com.innowise.authservice.repository.CredentialRepository;
import com.innowise.authservice.security.JwtTokenProvider;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDate;
import java.util.Optional;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock private CredentialRepository credentialRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private JwtTokenProvider jwtTokenProvider;
    @Mock private UserClient userClient;
    @Mock private CredentialMapper credentialMapper;

    @InjectMocks private AuthService authService;

    private Credential credential;

    @BeforeEach
    void setUp() {
        credential = new Credential();
        credential.setUsername("test@example.com");
        credential.setPasswordHash("hashed");
        credential.setRole(Role.USER);
        credential.setUserId(1L);
    }

    private RegisterRequest registerRequest() {
        RegisterRequest r = new RegisterRequest();
        r.setLogin("test@example.com");
        r.setPassword("Pass123!");
        r.setName("Alex");
        r.setSurname("Aleksandrov");
        r.setBirthDate(LocalDate.of(1989, 4, 8));
        r.setEmail("alex.aleksandrov@example.com");
        return r;
    }

    //register
    @Test
    void register_shouldCreateUserAndCredential() {
        RegisterRequest request = registerRequest();
        UserResponse userResponse = new UserResponse();
        userResponse.setId(1L);

        when(credentialRepository.existsByUsername("test@example.com")).thenReturn(false);
        when(userClient.createUser(any())).thenReturn(userResponse);
        when(credentialMapper.toEntity(request, 1L)).thenReturn(credential);
        when(passwordEncoder.encode("Pass123!")).thenReturn("hashed");

        authService.register(request);

        verify(userClient).createUser(any());
        verify(credentialRepository).save(credential);
        assertThat(credential.getPasswordHash()).isEqualTo("hashed");
        assertThat(credential.getRole()).isEqualTo(Role.USER);
        assertThat(credential.getUserId()).isEqualTo(1L);
    }

    @Test
    void register_shouldThrowConflictWhenLoginExists() {
        when(credentialRepository.existsByUsername("test@example.com")).thenReturn(true);

        assertThatThrownBy(() -> authService.register(registerRequest()))
                .isInstanceOf(ConflictException.class)
                .hasMessageContaining("Login already exists");

        verify(userClient, never()).createUser(any());
    }

    @Test
    void register_shouldRollbackWhenSaveFails() {
        RegisterRequest request = registerRequest();
        UserResponse userResponse = new UserResponse();
        userResponse.setId(1L);

        when(credentialRepository.existsByUsername("test@example.com")).thenReturn(false);
        when(userClient.createUser(any())).thenReturn(userResponse);
        when(credentialMapper.toEntity(request, 1L)).thenReturn(new Credential());
        when(passwordEncoder.encode(anyString())).thenReturn("hashed");
        when(credentialRepository.save(any())).thenThrow(new RuntimeException("DB error"));

        assertThatThrownBy(() -> authService.register(request))
                .isInstanceOf(RuntimeException.class);

        verify(userClient).deleteUser(1L);
    }

    //login
    @Test
    void login_shouldReturnTokens() {
        LoginRequest request = new LoginRequest();
        request.setLogin("test@example.com");
        request.setPassword("Pass123!");

        when(credentialRepository.findByUsername("test@example.com")).thenReturn(Optional.of(credential));
        when(passwordEncoder.matches("Pass123!", "hashed")).thenReturn(true);
        when(jwtTokenProvider.generateAccessToken(credential)).thenReturn("access");
        when(jwtTokenProvider.generateRefreshToken(credential)).thenReturn("refresh");

        TokenResponse response = authService.login(request);

        assertThat(response.getAccessToken()).isEqualTo("access");
        assertThat(response.getRefreshToken()).isEqualTo("refresh");
    }

    @Test
    void login_shouldThrowWhenPasswordWrong() {
        LoginRequest request = new LoginRequest();
        request.setLogin("test@example.com");
        request.setPassword("wrong");

        when(credentialRepository.findByUsername("test@example.com")).thenReturn(Optional.of(credential));
        when(passwordEncoder.matches("wrong", "hashed")).thenReturn(false);

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(BadCredentialsException.class);
    }

    //refresh
    @Test
    void refresh_shouldReturnNewTokens() {
        Claims claims = mock(Claims.class);
        when(claims.getSubject()).thenReturn("test@example.com");
        when(claims.get("type", String.class)).thenReturn("refresh");

        when(jwtTokenProvider.validateToken("refresh-token")).thenReturn(true);
        when(jwtTokenProvider.parseClaims("refresh-token")).thenReturn(claims);
        when(credentialRepository.findByUsername("test@example.com")).thenReturn(Optional.of(credential));
        when(jwtTokenProvider.generateAccessToken(credential)).thenReturn("new-access");
        when(jwtTokenProvider.generateRefreshToken(credential)).thenReturn("new-refresh");

        TokenResponse response = authService.refresh("refresh-token");

        assertThat(response.getAccessToken()).isEqualTo("new-access");
        assertThat(response.getRefreshToken()).isEqualTo("new-refresh");
    }

    @Test
    void refresh_shouldThrowWhenTokenIsAccess() {
        Claims claims = mock(Claims.class);
        when(claims.get("type", String.class)).thenReturn("access");

        when(jwtTokenProvider.validateToken("access-token")).thenReturn(true);
        when(jwtTokenProvider.parseClaims("access-token")).thenReturn(claims);

        assertThatThrownBy(() -> authService.refresh("access-token"))
                .isInstanceOf(UnauthorizedException.class)
                .hasMessageContaining("Not a refresh token");
    }

    @Test
    void refresh_shouldThrowWhenTokenInvalid() {
        when(jwtTokenProvider.validateToken("bad")).thenReturn(false);

        assertThatThrownBy(() -> authService.refresh("bad"))
                .isInstanceOf(UnauthorizedException.class);
    }
}
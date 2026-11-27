package com.innowise.authservice.controller;

import com.innowise.authservice.config.SecurityConfig;
import com.innowise.authservice.dto.TokenResponse;
import com.innowise.authservice.exception.UnauthorizedException;
import com.innowise.authservice.security.JwtTokenProvider;
import com.innowise.authservice.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.jpa.mapping.JpaMetamodelMappingContext;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;


@WebMvcTest(AuthController.class)
@Import(SecurityConfig.class)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuthService authService;
    @MockitoBean
    private JwtTokenProvider jwtTokenProvider;
    @MockitoBean
    private JpaMetamodelMappingContext jpaMetamodelMappingContext;

    //register
    @Test
    void register_returns201() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "login":"test@example.com",
                                  "password":"Pass123!",
                                  "name":"T",
                                  "surname":"U",
                                  "birthDate":"1990-01-01",
                                  "email":"test@example.com"
                                }
                                """))
                .andExpect(status().isCreated());
    }

    @Test
    void register_returns400WhenLoginBlank() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "login":"",
                                  "password":"Pass123!",
                                  "name":"T",
                                  "surname":"U",
                                  "birthDate":"1990-01-01",
                                  "email":"test@example.com"
                                }
                                """))
                .andExpect(status().isBadRequest());
    }

    @Test
    void register_returns400WhenEmailInvalid() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "login":"test@example.com",
                                  "password":"Pass123!",
                                  "name":"T",
                                  "surname":"U",
                                  "birthDate":"1990-01-01",
                                  "email":"not-an-email"
                                }
                                """))
                .andExpect(status().isBadRequest());
    }

    //login
    @Test
    void login_returns200() throws Exception {
        when(authService.login(any())).thenReturn(TokenResponse.builder()
                .accessToken("access").refreshToken("refresh").build());

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "login":"test@example.com",
                                  "password":"Pass123!"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("access"))
                .andExpect(jsonPath("$.refreshToken").value("refresh"));
    }

    //refresh
    @Test
    void refresh_returns200() throws Exception {
        when(authService.refresh("refresh")).thenReturn(TokenResponse.builder()
                .accessToken("new-access").refreshToken("new-refresh").build());

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "refreshToken":"refresh"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("new-access"));
    }

    //validate removed
    @Test
    void validate_returns404() throws Exception {
        mockMvc.perform(post("/api/auth/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "refreshToken":"test"
                                }
                                """))
                .andExpect(status().isNotFound());
    }

    //negative security
    @Test
    void refresh_withInvalidToken_returns401() throws Exception {
        when(authService.refresh("invalid")).thenThrow(new UnauthorizedException("Invalid refresh token"));

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"invalid\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void login_withWrongPassword_returns401() throws Exception {
        when(authService.login(any())).thenThrow(new BadCredentialsException("Invalid"));
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"login\":\"test@example.com\",\"password\":\"wrong\"}"))
                .andExpect(status().isUnauthorized());
    }
}
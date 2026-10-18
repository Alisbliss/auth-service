package com.innowise.authservice.dto;

import com.innowise.authservice.entity.Role;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter

public class RegisterRequest {
    @NotBlank
    private String login;
    @NotBlank
    private String password;
    @NotNull
    private Role role;
    @NotNull
    private Long userId;
}

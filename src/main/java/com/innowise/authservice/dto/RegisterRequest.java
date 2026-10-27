package com.innowise.authservice.dto;

import com.innowise.authservice.entity.Role;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter

public class RegisterRequest {
    @NotBlank(message = "login must not be blank")
    private String login;
    @NotBlank(message = "password must not be blank")
    private String password;
    @NotNull(message = "role must not be null")
    private Role role;
    @NotNull(message = "userId must not be null")
    private Long userId;
}

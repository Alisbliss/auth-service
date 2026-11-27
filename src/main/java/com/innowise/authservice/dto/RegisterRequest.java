package com.innowise.authservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Past;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDate;

@Getter
@Setter
public class RegisterRequest {
    @NotBlank(message = "login must not be blank")
    private String login;

    @NotBlank(message = "password must not be blank")
    @Size(min = 6, message = "password must be at least 6 characters")
    private String password;

    @NotBlank(message = "name must not be blank")
    private String name;

    @NotBlank(message = "surname must not be blank")
    private String surname;

    @NotNull(message = "birthDate must not be null")
    @Past(message = "birthDate must be in the past")
    private LocalDate birthDate;

    @NotBlank(message = "email must not be blank")
    @Email(message = "email must be valid")
    private String email;
}

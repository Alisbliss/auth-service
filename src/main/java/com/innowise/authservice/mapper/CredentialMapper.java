package com.innowise.authservice.mapper;

import com.innowise.authservice.dto.RegisterRequest;
import com.innowise.authservice.entity.Credential;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface CredentialMapper {

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "role", constant = "USER")
    @Mapping(target = "userId", source = "userId")
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "passwordHash", ignore = true)
    @Mapping(target = "username", source = "request.login")
    Credential toEntity(RegisterRequest request, Long userId);
}

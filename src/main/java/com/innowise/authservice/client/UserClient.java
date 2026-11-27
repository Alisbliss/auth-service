package com.innowise.authservice.client;

import com.innowise.authservice.dto.UserCreateRequest;
import com.innowise.authservice.dto.UserResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "user-service", url = "${services.user.url:http://localhost:8081}")
public interface UserClient {
    @PostMapping("/internal/users")
    UserResponse createUser(@RequestBody UserCreateRequest request);

    @DeleteMapping("/internal/users/{id}")
    void deleteUser(@PathVariable Long id);
}

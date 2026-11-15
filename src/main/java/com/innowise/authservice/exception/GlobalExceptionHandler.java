package com.innowise.authservice.exception;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.stream.Collectors;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleBadCredentials(BadCredentialsException e, HttpServletRequest r) {
        return build(HttpStatus.UNAUTHORIZED, "Invalid login or password", r.getRequestURI());
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleUsernameNotFound(UsernameNotFoundException e, HttpServletRequest r) {
        return build(HttpStatus.UNAUTHORIZED, "Invalid login or password", r.getRequestURI());
    }

    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<ErrorResponse> handleUnauthorized(UnauthorizedException e, HttpServletRequest request) {
        return build(HttpStatus.UNAUTHORIZED, e.getMessage(), request.getRequestURI());
    }

    @ExceptionHandler(io.jsonwebtoken.ExpiredJwtException.class)
    public ResponseEntity<ErrorResponse> handleExpiredJwt(
            io.jsonwebtoken.ExpiredJwtException e, HttpServletRequest r) {
        return build(HttpStatus.UNAUTHORIZED, "Token expired", r.getRequestURI());
    }

    @ExceptionHandler(io.jsonwebtoken.JwtException.class)
    public ResponseEntity<ErrorResponse> handleJwt(
            io.jsonwebtoken.JwtException e, HttpServletRequest r) {
        return build(HttpStatus.UNAUTHORIZED, "Invalid token", r.getRequestURI());
    }

    @ExceptionHandler(ConflictException.class)
    public ResponseEntity<ErrorResponse> handleConflict(ConflictException e, HttpServletRequest r) {
        return build(HttpStatus.CONFLICT, e.getMessage(), r.getRequestURI());
    }

    @ExceptionHandler(org.springframework.dao.DataIntegrityViolationException.class)
    public ResponseEntity<ErrorResponse> handleDataIntegrity(
            org.springframework.dao.DataIntegrityViolationException e, HttpServletRequest r) {
        return build(HttpStatus.CONFLICT, "Data conflict (duplicate or constraint violation)", r.getRequestURI());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidation(MethodArgumentNotValidException e, HttpServletRequest request) {
        String message = e.getBindingResult().getFieldErrors().stream()
                .map(fe -> fe.getField() + ": " + fe.getDefaultMessage())
                .collect(Collectors.joining("; "));
        return build(HttpStatus.BAD_REQUEST, message, request.getRequestURI());
    }

    @ExceptionHandler(org.springframework.http.converter.HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleNotReadable(
            org.springframework.http.converter.HttpMessageNotReadableException e, HttpServletRequest r) {
        return build(HttpStatus.BAD_REQUEST, "Malformed JSON request", r.getRequestURI());
    }

    @ExceptionHandler(org.springframework.web.servlet.resource.NoResourceFoundException.class)
    public ResponseEntity<ErrorResponse> handleNoResource(
            org.springframework.web.servlet.resource.NoResourceFoundException e, HttpServletRequest r) {
        return build(HttpStatus.NOT_FOUND, "Not Found", r.getRequestURI());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGeneral(Exception e, HttpServletRequest r) {
        log.error("Unexpected error at {}", r.getRequestURI(), e);
        return build(HttpStatus.INTERNAL_SERVER_ERROR, "Internal server error", r.getRequestURI());
    }

    private ResponseEntity<ErrorResponse> build(HttpStatus status, String message, String path) {
        return ResponseEntity.status(status).body(new ErrorResponse(
                LocalDateTime.now(ZoneOffset.UTC),
                status.value(),
                status.getReasonPhrase(),
                message,
                path));
    }
}

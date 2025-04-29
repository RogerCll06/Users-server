package visionaris.pe.dto.response;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({"username", "message", "status", "jwt"})
public record  AuthResponseDto(String email,
                               String message,
                               String jwt,
                               Boolean status) {
}
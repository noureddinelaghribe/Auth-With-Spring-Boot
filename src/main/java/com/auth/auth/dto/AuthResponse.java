package com.auth.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * Authentication response containing token and basic info.
 */
@Data
@AllArgsConstructor
public class AuthResponse {
    private String token;
    private String username;
    private String message;
}

package com.auth.auth.dto;

import lombok.Data;

/**
 * Partial update payload for user profile.
 */
@Data
public class UpdateUserRequest {
    private String username;
    private String email;
    private String password;
}

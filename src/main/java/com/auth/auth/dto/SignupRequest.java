package com.auth.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Signup request payload.
 * طلب إنشاء حساب.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SignupRequest {
    private String username;
    private String password;
    private String email;
}

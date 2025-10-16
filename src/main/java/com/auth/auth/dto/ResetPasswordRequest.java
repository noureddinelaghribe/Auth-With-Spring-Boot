package com.auth.auth.dto;

import lombok.Data;

@Data
public class ResetPasswordRequest {
    private String resetToken;
    private String newPassword;
}



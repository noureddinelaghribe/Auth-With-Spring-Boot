package com.auth.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * Simple wrapper for string messages in responses.
 */
@Data
@AllArgsConstructor
public class MessageResponse {
    private String message;
}

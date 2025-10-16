package com.auth.auth.controller;

import com.auth.auth.dto.MessageResponse;
import com.auth.auth.dto.UserResponse;
import com.auth.auth.model.User;
import com.auth.auth.repository.UserRepository;
import com.auth.auth.service.AccountService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Admin-only management endpoints: list users, change roles, reset passwords.
 */
@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
public class AdminController {

    private final AccountService accountService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    private String getCurrentUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication.getName();
    }

    /**
     * List all users (ADMIN only).
     */
    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<UserResponse>> listUsers() {
        String current = getCurrentUsername();
        List<UserResponse> users = accountService.getAllUsers(current);
        return ResponseEntity.ok(users);
    }

    /**
     * Change a user's role to USER or ADMIN (ADMIN only).
     */
    @PostMapping("/users/{id}/role")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> changeRole(@PathVariable Long id, @RequestBody Map<String, String> body) {
        String role = body.get("role");
        if (role == null || role.isBlank()) {
            return ResponseEntity.badRequest().body(new MessageResponse("role is required (USER or ADMIN)"));
        }
        User user = userRepository.findById(id).orElseThrow(() -> new RuntimeException("User not found"));
        user.setRole(role);
        userRepository.save(user);
        return ResponseEntity.ok(new MessageResponse("Role updated to " + role));
    }

    /**
     * Reset a user's password to a provided newPassword (ADMIN only).
     */
    @PostMapping("/users/{id}/reset-password")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> resetPassword(@PathVariable Long id, @RequestBody Map<String, String> body) {
        String newPassword = body.get("newPassword");
        if (newPassword == null || newPassword.isBlank()) {
            return ResponseEntity.badRequest().body(new MessageResponse("newPassword is required"));
        }
        User user = userRepository.findById(id).orElseThrow(() -> new RuntimeException("User not found"));
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        return ResponseEntity.ok(new MessageResponse("Password reset for user " + id));
    }
}



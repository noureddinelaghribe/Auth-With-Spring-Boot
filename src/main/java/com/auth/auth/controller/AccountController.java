package com.auth.auth.controller;

import com.auth.auth.dto.MessageResponse;
import com.auth.auth.dto.UpdateUserRequest;
import com.auth.auth.dto.UserResponse;
import com.auth.auth.service.AccountService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Account management endpoints for fetching and updating user profiles.
 * يتضمن نقاط الحصول على المستخدم الحالي، إدارة المستخدمين، والتحديث والحذف.
 */
@RestController
@RequestMapping("/api/account")
@RequiredArgsConstructor
public class AccountController {

    private final AccountService accountService;

    // Get current authenticated user's username from JWT
    private String getCurrentUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication.getName();
    }

    /**
     * Get the current authenticated user's profile.
     * @return the current user as {@link UserResponse}
     */
    @GetMapping("/me")
    public ResponseEntity<UserResponse> getCurrentUser() {
        try {
            String username = getCurrentUsername();
            UserResponse user = accountService.getCurrentUser(username);
            return ResponseEntity.ok(user);
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    /**
     * Get a user by id. Only allowed for the same user or admins.
     * @param id user id
     * @return {@link UserResponse} for the requested user
     */
    @GetMapping("/{id}")
    public ResponseEntity<?> getUserById(@PathVariable Long id) {
        try {
            String username = getCurrentUsername();
            UserResponse user = accountService.getUserById(id, username);
            return ResponseEntity.ok(user);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new MessageResponse(e.getMessage()));
        }
    }

    /**
     * Get all users. Admin-only operation.
     * @return list of users
     */
    @GetMapping("/all")
    public ResponseEntity<?> getAllUsers() {
        try {
            String username = getCurrentUsername();
            List<UserResponse> users = accountService.getAllUsers(username);
            return ResponseEntity.ok(users);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new MessageResponse(e.getMessage()));
        }
    }

    /**
     * Update a user profile. Allowed for the same user or admins.
     * @param id user id
     * @param request update request body
     * @return updated user response
     */
    @PutMapping("/{id}")
    public ResponseEntity<?> updateUser(
            @PathVariable Long id,
            @RequestBody UpdateUserRequest request) {
        try {
            String username = getCurrentUsername();
            UserResponse updatedUser = accountService.updateUser(id, request, username);
            return ResponseEntity.ok(updatedUser);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new MessageResponse(e.getMessage()));
        }
    }

    /**
     * Delete a user account. Allowed for the same user or admins.
     * @param id user id
     * @return message response on success
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        try {
            String username = getCurrentUsername();
            accountService.deleteUser(id, username);
            return ResponseEntity.ok(new MessageResponse("User deleted successfully"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new MessageResponse(e.getMessage()));
        }
    }
}

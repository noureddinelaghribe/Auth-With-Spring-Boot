package com.auth.auth.service;

import com.auth.auth.dto.UpdateUserRequest;
import com.auth.auth.dto.UserResponse;
import com.auth.auth.model.User;
import com.auth.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Business logic for reading/updating user accounts with simple role checks.
 * منطق إدارة الحسابات: عرض، تحديث، حذف مع التحقق من الصلاحيات.
 */
@Service
@RequiredArgsConstructor
public class AccountService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * Get the profile of the current authenticated user.
     */
    public UserResponse getCurrentUser(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        return mapToUserResponse(user);
    }

    /**
     * Get user by id. Allowed for self or ADMIN.
     */
    public UserResponse getUserById(Long id, String currentUsername) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        // Check if user is accessing their own account
        User currentUser = userRepository.findByUsername(currentUsername)
                .orElseThrow(() -> new RuntimeException("Current user not found"));
        
        if (!user.getId().equals(currentUser.getId()) && !"ADMIN".equals(currentUser.getRole())) {
            throw new RuntimeException("Access denied");
        }
        
        return mapToUserResponse(user);
    }

    /**
     * List all users. Only ADMIN can perform this action.
     */
    public List<UserResponse> getAllUsers(String currentUsername) {
        User currentUser = userRepository.findByUsername(currentUsername)
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        if (!"ADMIN".equals(currentUser.getRole())) {
            throw new RuntimeException("Access denied: Admin only");
        }
        
        return userRepository.findAll().stream()
                .map(this::mapToUserResponse)
                .collect(Collectors.toList());
    }

    /**
     * Update user fields. Allowed for self or ADMIN.
     */
    public UserResponse updateUser(Long id, UpdateUserRequest request, String currentUsername) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        // Check if user is updating their own account
        User currentUser = userRepository.findByUsername(currentUsername)
                .orElseThrow(() -> new RuntimeException("Current user not found"));
        
        if (!user.getId().equals(currentUser.getId()) && !"ADMIN".equals(currentUser.getRole())) {
            throw new RuntimeException("Access denied");
        }

        // Update fields if provided
        if (request.getUsername() != null && !request.getUsername().isEmpty()) {
            if (userRepository.existsByUsername(request.getUsername()) && 
                !user.getUsername().equals(request.getUsername())) {
                throw new RuntimeException("Username already exists");
            }
            user.setUsername(request.getUsername());
        }

        if (request.getEmail() != null && !request.getEmail().isEmpty()) {
            if (userRepository.existsByEmail(request.getEmail()) && 
                !user.getEmail().equals(request.getEmail())) {
                throw new RuntimeException("Email already exists");
            }
            user.setEmail(request.getEmail());
        }

        if (request.getPassword() != null && !request.getPassword().isEmpty()) {
            user.setPassword(passwordEncoder.encode(request.getPassword()));
        }

        User updatedUser = userRepository.save(user);
        return mapToUserResponse(updatedUser);
    }

    /**
     * Delete a user account. Allowed for self or ADMIN.
     */
    public void deleteUser(Long id, String currentUsername) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        // Check if user is deleting their own account
        User currentUser = userRepository.findByUsername(currentUsername)
                .orElseThrow(() -> new RuntimeException("Current user not found"));
        
        if (!user.getId().equals(currentUser.getId()) && !"ADMIN".equals(currentUser.getRole())) {
            throw new RuntimeException("Access denied");
        }

        userRepository.delete(user);
    }

    // Helper method to map User to UserResponse
    private UserResponse mapToUserResponse(User user) {
        return new UserResponse(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getRole()
        );
    }
}

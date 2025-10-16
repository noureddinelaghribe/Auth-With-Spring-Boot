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
 * منطق إدارة الحسابات: عرض ملف المستخدم، عرض مستخدم/كل المستخدمين، تحديث، حذف مع فحص الأدوار.
 */
@Service
@RequiredArgsConstructor
public class AccountService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * جلب ملف المستخدم الحالي.
     */
    public UserResponse getCurrentUser(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        return mapToUserResponse(user);
    }

    /**
     * جلب مستخدم بالمعرف. مسموح لصاحب الحساب نفسه أو ADMIN.
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
     * جلب كل المستخدمين. متاح لـ ADMIN فقط.
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
     * تحديث حقول مستخدم. مسموح لصاحب الحساب نفسه أو ADMIN.
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
     * حذف حساب مستخدم. مسموح لصاحب الحساب نفسه أو ADMIN.
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

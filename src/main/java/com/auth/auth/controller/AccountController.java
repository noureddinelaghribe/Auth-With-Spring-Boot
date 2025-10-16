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
 * نقاط إدارة الحساب: جلب الملف الشخصي للمستخدم الحالي، عرض/تحديث/حذف مستخدمين.
 */
@RestController
@RequestMapping("/api/account")
@RequiredArgsConstructor
public class AccountController {

    private final AccountService accountService;

    /**
     * الحصول على اسم المستخدم الحالي من الـ JWT عبر SecurityContext.
     */
    private String getCurrentUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication.getName();
    }

    /**
     * جلب ملف المستخدم الحالي.
     * @return {@link UserResponse} للمستخدم الحالي
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
     * جلب مستخدم عبر المعرف. مسموح لصاحب الحساب نفسه أو للمشرف ADMIN.
     * @param id معرف المستخدم
     * @return {@link UserResponse} للمستخدم المطلوب
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
     * جلب كل المستخدمين. (ADMIN فقط)
     * @return قائمة المستخدمين
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
     * تحديث ملف مستخدم. مسموح لصاحب الحساب نفسه أو للمشرف ADMIN.
     * @param id معرف المستخدم
     * @param request جسم الطلب للتحديث
     * @return {@link UserResponse} بعد التحديث
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
     * حذف حساب مستخدم. مسموح لصاحب الحساب نفسه أو للمشرف ADMIN.
     * @param id معرف المستخدم
     * @return رسالة نجاح
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

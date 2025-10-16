package com.auth.auth.controller;



import com.auth.auth.dto.AuthResponse;
import com.auth.auth.dto.LoginRequest;
import com.auth.auth.dto.MessageResponse;
import com.auth.auth.dto.SignupRequest;
import com.auth.auth.dto.ForgotPasswordRequest;
import com.auth.auth.dto.VerifyOtpRequest;
import com.auth.auth.dto.ResetPasswordRequest;
import com.auth.auth.service.AuthService;
import com.auth.auth.service.PasswordResetService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * REST endpoints for authentication flows.
 * يوفر نقاط النهاية لتسجيل المستخدمين وتسجيل الدخول والوصول إلى صفحة محمية.
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final PasswordResetService passwordResetService;

    /**
     * Register a new user.
     * @param request signup payload containing username, password, and email
     * @return message response on success or error message on failure
     */
    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@RequestBody SignupRequest request) {
        try {
            String message = authService.registerUser(
                    request.getUsername(),
                    request.getPassword(),
                    request.getEmail()
            );
            return ResponseEntity.ok(new MessageResponse(message));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new MessageResponse(e.getMessage()));
        }
    }

    /**
     * Authenticate a user and return a JWT token.
     * @param request login payload containing username and password
     * @return {@link AuthResponse} with token and username on success
     */
    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody LoginRequest request) {
        try {
            String token = authService.loginUser(
                    request.getUsername(),
                    request.getPassword()
            );
            return ResponseEntity.ok(new AuthResponse(
                    token,
                    request.getUsername(),
                    "تم تسجيل الدخول بنجاح!"
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new MessageResponse(e.getMessage()));
        }
    }

    /**
     * Example of a protected endpoint to verify JWT protection.
     * @return simple protected message
     */
    @GetMapping("/profile")
    public ResponseEntity<?> getProfile() {
        return ResponseEntity.ok(new MessageResponse("مرحباً! هذه صفحة محمية"));
    }

    /**
     * Request OTP to reset password. Accepts email or username in email field.
     */
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody ForgotPasswordRequest request) {
        try {
            passwordResetService.requestOtp(request.getEmail());
        } catch (Exception ignored) { }
        return ResponseEntity.ok(new MessageResponse("If the email exists, an OTP was sent"));
    }

    /**
     * Verify received OTP and return a short-lived reset token.
     */
    @PostMapping("/verify-otp")
    public ResponseEntity<?> verifyOtp(@RequestBody VerifyOtpRequest request) {
        try {
            String resetToken = passwordResetService.verifyOtp(request.getEmail(), request.getOtp());
            return ResponseEntity.ok(new MessageResponse(resetToken));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new MessageResponse(e.getMessage()));
        }
    }

    /**
     * Reset password using the provided reset token.
     */
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody ResetPasswordRequest request) {
        try {
            passwordResetService.resetPassword(request.getResetToken(), request.getNewPassword());
            return ResponseEntity.ok(new MessageResponse("Password reset successfully"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new MessageResponse(e.getMessage()));
        }
    }
}
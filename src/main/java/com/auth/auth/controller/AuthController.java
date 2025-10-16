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
 * واجهة REST للمصادقة: تسجيل، تسجيل دخول، صفحة محمية، واسترجاع كلمة المرور عبر OTP.
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final PasswordResetService passwordResetService;

    /**
     * تسجيل مستخدم جديد.
     * @param request بيانات التسجيل (username, password, email)
     * @return رسالة نجاح أو رسالة خطأ
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
     * تسجيل الدخول وإرجاع توكن JWT عند النجاح.
     * @param request بيانات الدخول (username, password)
     * @return {@link AuthResponse} يحوي التوكن واسم المستخدم
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
     * مثال لنقطة محمية للتحقق من عمل الحماية بـ JWT.
     * @return رسالة بسيطة
     */
    @GetMapping("/profile")
    public ResponseEntity<?> getProfile() {
        return ResponseEntity.ok(new MessageResponse("مرحباً! هذه صفحة محمية"));
    }

    /**
     * طلب إرسال OTP إلى البريد لإعادة تعيين كلمة المرور.
     * يقبل البريد أو اسم المستخدم في حقل email.
     */
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody ForgotPasswordRequest request) {
        try {
            passwordResetService.requestOtp(request.getEmail());
        } catch (Exception ignored) { }
        return ResponseEntity.ok(new MessageResponse("If the email exists, an OTP was sent"));
    }

    /**
     * التحقق من كود OTP المُرسل، وإرجاع رمز مؤقت (resetToken) لإتمام التغيير.
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
     * إعادة تعيين كلمة المرور باستخدام الرمز المؤقت resetToken.
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
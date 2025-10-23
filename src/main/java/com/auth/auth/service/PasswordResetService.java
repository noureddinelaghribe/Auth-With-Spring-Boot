package com.auth.auth.service;

import com.auth.auth.model.PasswordResetToken;
import com.auth.auth.model.User;
import com.auth.auth.repository.PasswordResetTokenRepository;
import com.auth.auth.repository.UserRepository;
import com.auth.auth.dto.OtpVerifyResponse;
import com.auth.auth.dto.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Random;
import java.util.UUID;

/**
 * خدمة استرجاع كلمة المرور عبر OTP:
 * - طلب إرسال OTP للبريد
 * - التحقق من OTP وإصدار رمز مؤقت
 * - إعادة تعيين كلمة المرور باستخدام الرمز المؤقت
 */
@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    private static final Duration OTP_TTL = Duration.ofMinutes(10);
    private static final Duration RESET_TOKEN_TTL = Duration.ofMinutes(15);
    private static final int MAX_ATTEMPTS = 5;

    /**
     * طلب توليد وإرسال OTP إلى بريد المستخدم (أو اسم المستخدم).
     */
    public void requestOtp(String email) {
        userRepository.findByUsername(email); // no-op just to use repository
        User user = userRepository.findByUsername(email).orElseGet(() -> userRepository.findByEmail(email).orElse(null));
        if (user == null) {
            // Do not reveal existence
            return;
        }

        PasswordResetToken existing = tokenRepository.findByUser(user).orElse(new PasswordResetToken());
        existing.setUser(user);
        String otp = generateNumericOtp(6);
        existing.setOtpHash(passwordEncoder.encode(otp));
        existing.setOtpExpiresAt(Instant.now().plus(OTP_TTL));
        existing.setAttempts(0);
        existing.setLockedUntil(null);
        existing.setResetToken(null);
        existing.setResetTokenExpiresAt(null);
        tokenRepository.save(existing);

        emailService.sendOtpEmail(user.getEmail(), otp);
    }

    /**
     * التحقق من OTP المُرسل وإصدار resetToken قصير العمر عند النجاح.
     */
    public OtpVerifyResponse verifyOtp(String email, String otp) {
        User user = userRepository.findByUsername(email).orElseGet(() -> userRepository.findByEmail(email).orElse(null));
        if (user == null) {
            return new OtpVerifyResponse(false, "Invalid or expired OTP.", null);
        }
        PasswordResetToken token = tokenRepository.findByUser(user).orElse(null);
        if (token == null) {
            return new OtpVerifyResponse(false, "Invalid or expired OTP.", null);
        }

        Instant now = Instant.now();
        if (token.getLockedUntil() != null && now.isBefore(token.getLockedUntil())) {
            return new OtpVerifyResponse(false, "Invalid or expired OTP.", null);
        }
        if (token.getOtpExpiresAt() == null || now.isAfter(token.getOtpExpiresAt())) {
            return new OtpVerifyResponse(false, "Invalid or expired OTP.", null);
        }
        if (!passwordEncoder.matches(otp, token.getOtpHash())) {
            int attempts = token.getAttempts() + 1;
            token.setAttempts(attempts);
            if (attempts >= MAX_ATTEMPTS) {
                token.setLockedUntil(now.plus(Duration.ofMinutes(15)));
            }
            tokenRepository.save(token);
            return new OtpVerifyResponse(false, "Invalid or expired OTP.", null);
        }

        // success -> issue reset token
        String resetToken = UUID.randomUUID().toString();
        token.setResetToken(resetToken);
        token.setResetTokenExpiresAt(now.plus(RESET_TOKEN_TTL));
        tokenRepository.save(token);
        return new OtpVerifyResponse(true, "OTP verified successfully.", resetToken);
    }

    /**
     * إعادة تعيين كلمة المرور باستخدام resetToken.
     */
    public ApiResponse resetPassword(String resetToken, String newPassword) {
        PasswordResetToken token = tokenRepository.findByResetToken(resetToken).orElse(null);
        if (token == null || token.getResetTokenExpiresAt() == null || Instant.now().isAfter(token.getResetTokenExpiresAt())) {
            return new ApiResponse(false, "Reset token is invalid or has expired.");
        }
        User user = token.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        // invalidate
        token.setResetToken(null);
        token.setResetTokenExpiresAt(null);
        tokenRepository.save(token);
        return new ApiResponse(true, "Password has been reset successfully.");
    }

    private String generateNumericOtp(int length) {
        Random random = new SecureRandom();
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) sb.append(random.nextInt(10));
        return sb.toString();
    }
}



package com.auth.auth.service;

import com.auth.auth.model.PasswordResetToken;
import com.auth.auth.model.User;
import com.auth.auth.repository.PasswordResetTokenRepository;
import com.auth.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Random;
import java.util.UUID;

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

    public String verifyOtp(String email, String otp) {
        User user = userRepository.findByUsername(email).orElseGet(() -> userRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found")));
        PasswordResetToken token = tokenRepository.findByUser(user).orElseThrow(() -> new RuntimeException("OTP not requested"));

        Instant now = Instant.now();
        if (token.getLockedUntil() != null && now.isBefore(token.getLockedUntil())) {
            throw new RuntimeException("Too many attempts. Try later");
        }
        if (token.getOtpExpiresAt() == null || now.isAfter(token.getOtpExpiresAt())) {
            throw new RuntimeException("OTP expired");
        }
        if (!passwordEncoder.matches(otp, token.getOtpHash())) {
            int attempts = token.getAttempts() + 1;
            token.setAttempts(attempts);
            if (attempts >= MAX_ATTEMPTS) {
                token.setLockedUntil(now.plus(Duration.ofMinutes(15)));
            }
            tokenRepository.save(token);
            throw new RuntimeException("Invalid OTP");
        }

        // success -> issue reset token
        String resetToken = UUID.randomUUID().toString();
        token.setResetToken(resetToken);
        token.setResetTokenExpiresAt(now.plus(RESET_TOKEN_TTL));
        tokenRepository.save(token);
        return resetToken;
    }

    public void resetPassword(String resetToken, String newPassword) {
        PasswordResetToken token = tokenRepository.findByResetToken(resetToken).orElseThrow(() -> new RuntimeException("Invalid token"));
        if (token.getResetTokenExpiresAt() == null || Instant.now().isAfter(token.getResetTokenExpiresAt())) {
            throw new RuntimeException("Token expired");
        }
        User user = token.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        // invalidate
        token.setResetToken(null);
        token.setResetTokenExpiresAt(null);
        tokenRepository.save(token);
    }

    private String generateNumericOtp(int length) {
        Random random = new SecureRandom();
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) sb.append(random.nextInt(10));
        return sb.toString();
    }
}



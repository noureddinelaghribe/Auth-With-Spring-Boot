package com.auth.auth.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * كيان لحفظ بيانات OTP والرمز المؤقت لإعادة تعيين كلمة المرور.
 */
@Entity
@Table(name = "password_reset_tokens")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class PasswordResetToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    /** Hashed OTP value (e.g., BCrypt) */
    @Column(name = "otp_hash")
    private String otpHash;

    /** When the OTP expires */
    @Column(name = "otp_expires_at")
    private Instant otpExpiresAt;

    /** Number of verification attempts used */
    @Column(name = "attempts")
    private int attempts;

    /** If set, block verification until this time */
    @Column(name = "locked_until")
    private Instant lockedUntil;

    /** One-time token returned after successful OTP verification */
    @Column(name = "reset_token")
    private String resetToken;

    /** When the reset token expires */
    @Column(name = "reset_token_expires_at")
    private Instant resetTokenExpiresAt;
}



package com.auth.auth.repository;

import com.auth.auth.model.PasswordResetToken;
import com.auth.auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {
    Optional<PasswordResetToken> findByUser(User user);
    Optional<PasswordResetToken> findByResetToken(String resetToken);
}



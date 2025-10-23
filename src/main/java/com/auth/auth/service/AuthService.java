package com.auth.auth.service;

import com.auth.auth.dto.ApiResponse;
import com.auth.auth.dto.LoginResponse;
import com.auth.auth.model.User;
import com.auth.auth.repository.UserRepository;
import com.auth.auth.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * خدمة المصادقة: تسجيل مستخدمين جدد، التحقق من بيانات الدخول، وتوليد JWT.
 */
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    /**
     * تسجيل مستخدم جديد بعد التحقق من عدم تكرار الاسم والبريد.
     * @return رسالة نجاح
     */
    public ApiResponse registerUser(String username, String password, String email) {

        // التحقق من وجود المستخدم
//        if (userRepository.existsByUsername(username)) {
//            return new ApiResponse(false, "Username already exists.");
//        }

        if (userRepository.existsByEmail(email)) {
            return new ApiResponse(false, "Email already exists. Please log in instead.");
        }

        // إنشاء مستخدم جديد
        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password)); // تشفير كلمة المرور
        user.setEmail(email);
        user.setRole("USER");

        userRepository.save(user);

        return new ApiResponse(true, "Account created successfully.");
    }

    /**
     * التحقق من بيانات الدخول وإرجاع استجابة منظمة مع JWT عند النجاح.
     */
    public LoginResponse loginUser(String email, String password) {

        // البحث عن المستخدم بالبريد الإلكتروني
        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null) {
            return new LoginResponse(false, "Invalid email or password.", null);
        }

        // التحقق من كلمة المرور
        if (!passwordEncoder.matches(password, user.getPassword())) {
            return new LoginResponse(false, "Invalid email or password.", null);
        }

        // توليد JWT Token مع البريد كموضوع
        String token = jwtUtil.generateToken(email);
        return new LoginResponse(true, "Login successful.", token);
    }
}
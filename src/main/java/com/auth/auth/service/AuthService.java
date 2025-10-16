package com.auth.auth.service;



import com.auth.auth.model.User;
import com.auth.auth.repository.UserRepository;
import com.auth.auth.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * Authentication service encapsulating registration and login logic.
 * خدمة المصادقة: تسجيل مستخدمين جدد وتسجيل الدخول وتوليد JWT.
 */
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    /**
     * Register a new user with unique username and email.
     * @return success message
     */
    public String registerUser(String username, String password, String email) {

        // التحقق من وجود المستخدم
        if (userRepository.existsByUsername(username)) {
            throw new RuntimeException("اسم المستخدم موجود بالفعل!");
        }

        if (userRepository.existsByEmail(email)) {
            throw new RuntimeException("البريد الإلكتروني مستخدم بالفعل!");
        }

        // إنشاء مستخدم جديد
        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password)); // تشفير كلمة المرور
        user.setEmail(email);
        user.setRole("USER");

        userRepository.save(user);

        return "تم التسجيل بنجاح!";
    }

    /**
     * Authenticate user credentials and return a signed JWT token.
     */
    public String loginUser(String username, String password) {

        // البحث عن المستخدم
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("اسم المستخدم أو كلمة المرور خاطئة!"));

        // التحقق من كلمة المرور
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("اسم المستخدم أو كلمة المرور خاطئة!");
        }

        // توليد JWT Token
        return jwtUtil.generateToken(username);
    }
}
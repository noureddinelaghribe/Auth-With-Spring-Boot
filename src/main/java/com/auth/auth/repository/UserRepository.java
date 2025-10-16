package com.auth.auth.repository;


import com.auth.auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

/**
 * Repository for CRUD and lookup operations on {@link User}.
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    // البحث عن مستخدم بالاسم
    Optional<User> findByUsername(String username);

    // البحث عن مستخدم بالبريد الإلكتروني
    Optional<User> findByEmail(String email);

    // التحقق إذا كان الاسم موجود
    Boolean existsByUsername(String username);

    // التحقق إذا كان الإيميل موجود
    Boolean existsByEmail(String email);
}
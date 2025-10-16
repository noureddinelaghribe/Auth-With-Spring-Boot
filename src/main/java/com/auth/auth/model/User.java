package com.auth.auth.model;


import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

/**
 * JPA entity representing application users.
 * الكيان المسؤول عن تخزين بيانات المستخدم الأساسية.
 */
@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(unique = true, nullable = false)
    private String email;

    /**
     * Role name such as "USER" or "ADMIN" used by Spring Security.
     */
    private String role; // مثل: "USER" أو "ADMIN"
}
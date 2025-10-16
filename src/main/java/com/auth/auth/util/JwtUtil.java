package com.auth.auth.util;


import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

/**
 * أداة للتعامل مع JWT: توليد التوكن، استخراج البيانات، والتحقق من الصلاحية.
 */
@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private Long expiration;

    // إنشاء مفتاح التشفير
    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }


    /**
     * توليد JWT موقّع لاسم المستخدم المرسل.
     */
    public String generateToken(String username) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);

        return Jwts.builder()
                .setSubject(username) // اسم المستخدم
                .setIssuedAt(now) // وقت الإصدار
                .setExpiration(expiryDate) // وقت انتهاء الصلاحية
                .signWith(getSigningKey()) // التوقيع
                .compact();
    }


    /**
     * استخراج اسم المستخدم (subject) من التوكن.
     */
    public String getUsernameFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(getSigningKey())   // لاحظ: لازم يكون مفاتيح Key من نوع SecretKey أو PublicKey
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return claims.getSubject();
    }

    /**
     * التحقق من التوقيع وصلاحية التوكن.
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(getSigningKey())   // مفتاح التوقيع
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }



}

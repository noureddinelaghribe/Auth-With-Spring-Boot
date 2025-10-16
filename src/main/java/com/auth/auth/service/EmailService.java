package com.auth.auth.service;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    @Autowired
    private ObjectProvider<JavaMailSender> mailSenderProvider;

    public void sendOtpEmail(String to, String otp) {
        JavaMailSender mailSender = mailSenderProvider.getIfAvailable();
        if (mailSender == null) {
            // In test or dev without mail configuration, skip sending
            return;
        }
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("Password Reset OTP");
        message.setText("Your OTP code is: " + otp + "\nIt will expire in 10 minutes.");
        mailSender.send(message);
    }
}

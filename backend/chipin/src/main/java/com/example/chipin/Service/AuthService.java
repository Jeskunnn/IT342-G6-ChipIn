package com.example.chipin.Service;

import com.example.chipin.DTO.LoginRequest;
import com.example.chipin.DTO.LoginResponse;
import com.example.chipin.Entity.UserEntity;
import com.example.chipin.Repository.UserRepository;
import com.example.chipin.Security.JwtUtil;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final BCryptPasswordEncoder passwordEncoder;

    public AuthService(UserRepository userRepository, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
        this.passwordEncoder = new BCryptPasswordEncoder();
    }

    public LoginResponse login(LoginRequest request) {
        Optional<UserEntity> userOpt = userRepository.findByEmail(request.getEmail());
        if (userOpt.isPresent()) {
            UserEntity user = userOpt.get();
            if (passwordEncoder.matches(request.getPassword(), user.getPassword())) {
                String token = jwtUtil.generateToken(user.getEmail());
                return new LoginResponse("Login successful", token);
            }
        }
        throw new RuntimeException("Invalid email or password");
    }
}

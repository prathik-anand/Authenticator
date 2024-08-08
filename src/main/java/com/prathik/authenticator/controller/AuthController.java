package com.prathik.authenticator.controller;

import com.prathik.authenticator.config.JwtUtil;
import com.prathik.authenticator.dto.LoginRequest;
import com.prathik.authenticator.model.AppUser;
import com.prathik.authenticator.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final UserService userService;

    @Autowired
    public AuthController(AuthenticationManager authenticationManager, JwtUtil jwtUtil, UserService userService) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.userService = userService;
    }

    @PostMapping("login")
    public ResponseEntity<String> authenticateUser(@RequestBody LoginRequest loginRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

            String token = jwtUtil.generateToken(loginRequest.getUsername());

            return ResponseEntity.ok(token);
        } catch (Exception e) {
            return ResponseEntity.status(401).body("Invalid credentials");
        }
    }

    @PostMapping("register")
    public ResponseEntity<?> registerUser(@RequestBody AppUser appUser) {
        if (userService.findByUsername(appUser.getUsername()) != null) {
            return ResponseEntity.badRequest().body("Username is already taken");
        }

        appUser.setRoleId(0); // Set default role to 0 (User)
        userService.saveUser(appUser);

        return ResponseEntity.ok("User registered successfully");
    }
}

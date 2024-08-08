package com.prathik.authenticator.service;

import com.prathik.authenticator.model.AppUser;
import com.prathik.authenticator.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public AppUser saveUser(AppUser appUser) {
        appUser.setPassword(passwordEncoder.encode(appUser.getPassword()));
        return userRepository.save(appUser);
    }

    public AppUser findByUsername(String username) {
        return userRepository.findByUsername(username).orElse(null);
    }

    public void updateRole(Long userId, Integer roleId) {
        AppUser appUser = userRepository.findById(userId).orElseThrow(() -> new IllegalArgumentException("User not found"));
        appUser.setRoleId(roleId);
        userRepository.save(appUser);
    }
}

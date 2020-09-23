package com.bluelagoon.blmanagement.service;

import com.bluelagoon.blmanagement.dto.LoginRequest;
import com.bluelagoon.blmanagement.dto.LoginResponse;
import com.bluelagoon.blmanagement.dto.MessageResponse;
import com.bluelagoon.blmanagement.dto.SignUpRequest;
import com.bluelagoon.blmanagement.model.ERole;
import com.bluelagoon.blmanagement.model.Role;
import com.bluelagoon.blmanagement.model.User;
import com.bluelagoon.blmanagement.repository.RoleRepository;
import com.bluelagoon.blmanagement.repository.UserRepository;
import com.bluelagoon.blmanagement.security.JwtUtils;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
@Slf4j
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;
    private final JwtUtils jwtUtils;

    @Transactional
    public LoginResponse login(LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),
                        loginRequest.getPassword())
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        return LoginResponse.builder()
                .token(jwt)
                .userId(userDetails.getUserId())
                .username(userDetails.getUsername())
                .email(userDetails.getEmail())
                .roles(roles)
                .build();
    }

    @Transactional
    public ResponseEntity<MessageResponse> signUp(SignUpRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("ERROR: username is already taken!"));
        } else if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("ERROR: email is already in use!"));
        } else {
            List<String> strRoles = signUpRequest.getRoles();
            List<Role> roles = new ArrayList<>();

            if (strRoles == null) {
                Role userRole = roleRepository.findByRoleName(ERole.ROLE_USER)
                        .orElseThrow(() -> new RuntimeException("ERROR! User Role not found!!"));
                roles.add(userRole);
            } else {
                strRoles.forEach(role -> {
                    if (role.equalsIgnoreCase("admin")) {
                        Role adminRole = roleRepository.findByRoleName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("ERROR! Admin role not found"));
                        roles.add(adminRole);
                    } else if (role.equalsIgnoreCase("mod")) {
                        Role modRole = roleRepository.findByRoleName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("ERROR! Mod role not found"));
                        roles.add(modRole);
                    } else if (role.equalsIgnoreCase("user")) {
                        Role userRole = roleRepository.findByRoleName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("ERROR! User Role not found"));
                        roles.add(userRole);
                    } else {
                        throw new RuntimeException("INVALID ROLE");
                    }
                });
            }
            User user = new User();
            user.setUsername(signUpRequest.getUsername());
            user.setEmail(signUpRequest.getEmail());
            user.setPassword(encoder.encode(signUpRequest.getPassword()));
            user.setPhoneNumber(signUpRequest.getPhoneNumber());
            user.setRoles(roles);
            userRepository.save(user);

            return ResponseEntity
                    .status(HttpStatus.CREATED)
                    .body(new MessageResponse("User registered successfully!"));
        }
    }
}

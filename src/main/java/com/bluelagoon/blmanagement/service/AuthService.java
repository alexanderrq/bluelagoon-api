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
import java.util.HashSet;
import java.util.List;
import java.util.Set;
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
            Set<Role> roles = new HashSet<>();

            if (strRoles == null) {
                log.info("role admin", roleRepository.findByRoleName(ERole.ROLE_ADMIN));
                log.info("role user", roleRepository.findByRoleName(ERole.ROLE_USER));
                log.info("role mod", roleRepository.findByRoleName(ERole.ROLE_MODERATOR));
                Role userRole = roleRepository.findByRoleName(ERole.ROLE_USER)
                        .orElseThrow(() -> new RuntimeException("ERROR: Role is not found!"));
                roles.add(userRole);
            } else {
                strRoles.forEach(role -> {
                    switch (role) {
                        case "admin":
                            Role adminRole = roleRepository.findByRoleName(ERole.ROLE_ADMIN)
                                    .orElseThrow(() -> new RuntimeException("ERROR: Role is not found!"));
                            roles.add(adminRole);
                            break;
                        case "mod":
                            Role modRole = roleRepository.findByRoleName(ERole.ROLE_MODERATOR)
                                    .orElseThrow(() -> new RuntimeException("ERROR: Role is not found!"));
                            roles.add(modRole);
                            break;
                        case "user":
                            Role userRole = roleRepository.findByRoleName(ERole.ROLE_USER)
                                    .orElseThrow(() -> new RuntimeException("ERROR: Role is not found!"));
                            roles.add(userRole);
                        default:
                            throw new RuntimeException("ERROR: INVALID ROLE REQUEST");
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

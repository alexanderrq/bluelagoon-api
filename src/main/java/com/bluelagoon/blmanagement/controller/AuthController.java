package com.bluelagoon.blmanagement.controller;

import com.bluelagoon.blmanagement.dto.LoginRequest;
import com.bluelagoon.blmanagement.dto.LoginResponse;
import com.bluelagoon.blmanagement.dto.MessageResponse;
import com.bluelagoon.blmanagement.dto.SignUpRequest;
import com.bluelagoon.blmanagement.model.Role;
import com.bluelagoon.blmanagement.repository.RoleRepository;
import com.bluelagoon.blmanagement.service.AuthService;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

import static com.bluelagoon.blmanagement.model.ERole.*;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*", maxAge = 3600)
@AllArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final RoleRepository roleRepository;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest loginRequest) {
        return ResponseEntity
                .status(HttpStatus.OK)
                .body(authService.login(loginRequest));
    }

    @PostMapping("/signup")
    public ResponseEntity<MessageResponse> signUp(@Valid @RequestBody SignUpRequest signUpRequest) {
        return authService.signUp(signUpRequest);
    }
}

package visionaris.pe.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import visionaris.pe.dto.request.AuthLoginRequest;
import visionaris.pe.dto.request.AuthRegisterRequest;
import visionaris.pe.dto.response.AuthResponseDto;
import visionaris.pe.service.UserServiceImpl;


@RestController
@RequestMapping("/auth")
public class AuthController {


    private final UserServiceImpl userService;

    public AuthController(UserServiceImpl userService) {
        this.userService = userService;
    }

    /**
     * Endpoint de registro.
     * Valida la entrada y devuelve un JWT si el registro fue exitoso.
     */
    @PostMapping("/register")
    public ResponseEntity<AuthResponseDto> register(
            @Valid @RequestBody AuthRegisterRequest registerRequest) {
        AuthResponseDto response = userService.register(registerRequest);
        return ResponseEntity.ok(response);
    }

    /**
     * Endpoint de login.
     * Valida la entrada y devuelve un JWT si las credenciales son correctas.
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponseDto> login(
            @Valid @RequestBody AuthLoginRequest loginRequest) {
        AuthResponseDto response = userService.login(loginRequest);
        return ResponseEntity.ok(response);
    }
}

package visionaris.pe.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import visionaris.pe.config.jwt.JwtUtils;
import visionaris.pe.dto.request.AuthLoginRequest;
import visionaris.pe.dto.request.AuthRegisterRequest;
import visionaris.pe.dto.response.AuthResponseDto;
import visionaris.pe.entity.Users;
import visionaris.pe.repository.UsersRepository;

@Service

public class UserServiceImpl  {
    private final UsersRepository usersRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;

    public UserServiceImpl(UsersRepository usersRepository, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager, JwtUtils jwtUtils) {
        this.usersRepository = usersRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
    }


    public AuthResponseDto register(AuthRegisterRequest request) {
        // 1. Verificar unicidad del email
        if (usersRepository.findByEmail(request.email()).isPresent()) {
            throw new IllegalArgumentException("El correo ya está registrado");
        }

        // 2. Crear y guardar la entidad Users
        Users user = new Users();
        user.setEmail(request.email());
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setName(request.name());
        user.setPhone(request.phone());
        user.setCity(request.city());
        usersRepository.save(user);

        // 3. Generar token JWT
        String token = jwtUtils.createToken(
                new UsernamePasswordAuthenticationToken(request.email(), request.password())
        );

        // 4. Devolver respuesta
        return new AuthResponseDto(
                request.email(),
                "Registro exitoso",
                token,
                true
        );
    }

    /**
     * Autentica un usuario existente y devuelve un token JWT.
     */
    public AuthResponseDto login(AuthLoginRequest request) {
        // 1. Carga el usuario (tu UserDetailsService)
        Users user = usersRepository.findByEmail(request.email())
                .orElseThrow(() -> new BadCredentialsException("Credenciales incorrectas"));

        // 2. Verifica la contraseña
        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new BadCredentialsException("Credenciales incorrectas");
        }

        // 3. Genera el token
        String token = jwtUtils.createToken(
                new UsernamePasswordAuthenticationToken(user.getEmail(), request.password())
        );

        // 4. Responde
        return new AuthResponseDto(user.getEmail(), "Login exitoso", token, true);
    }
}

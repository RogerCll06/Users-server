package visionaris.pe.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import visionaris.pe.config.jwt.JwtUtils;
import visionaris.pe.config.filter.JwtAuthenticationFilter;
@Configuration
@EnableWebSecurity
public class SecurityConfig {


    private final JwtUtils jwtUtils;

    public SecurityConfig(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }


    // @Autowired
   // private JwtAuthenticationFilter jwtAuthenticationFilter;  // Asegúrate de que esta clase esté implementada correctamente

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(csrf -> csrf.disable())  // Deshabilitar protección CSRF (si no la necesitas)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))  // Sin sesiones
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html", "/swagger-ui/index.html", "/auth/**", "/").permitAll()  // Rutas públicas
                        .anyRequest().authenticated()  // Rutas privadas que requieren autenticación
                )
                .addFilterBefore(new JwtAuthenticationFilter(jwtUtils), BasicAuthenticationFilter.class)
                .build();
    }

    // Definir un bean para AuthenticationManager
    @Bean
    public AuthenticationManager authManager(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity.getSharedObject(AuthenticationManagerBuilder.class)
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}

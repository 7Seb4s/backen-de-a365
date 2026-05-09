package com.backdea365.app.config;

import com.backdea365.app.security.FiltroJWT;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

// Configura la seguridad del backend: rutas publicas, CORS, JWT y headers para Google
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class ConfiguracionSeguridad {

    private final FiltroJWT filtroJWT;
    private final UserDetailsService userDetailsService;

    // Define que rutas son publicas y cuales requieren token JWT
    @Bean
    public SecurityFilterChain cadenaFiltros(HttpSecurity http) throws Exception {
        return http
                // Desactiva CSRF porque usamos JWT, no sesiones de navegador
                .csrf(csrf -> csrf.disable())

                // Activa CORS para que Angular en localhost:4200 pueda conectarse
                .cors(cors -> cors.configurationSource(configuracionCors()))

                // Headers necesarios para que el popup de Google Sign-In funcione
                .headers(headers -> headers
                        .frameOptions(frame -> frame.sameOrigin())
                        .addHeaderWriter((request, response) -> {
                            response.setHeader("Cross-Origin-Opener-Policy", "same-origin-allow-popups");
                            response.setHeader("Cross-Origin-Embedder-Policy", "unsafe-none");
                        })
                )

                // Rutas publicas: no necesitan token JWT para acceder
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/api/auth/login",               // login con codigo + contrasena
                                "/api/auth/google",              // login con Google
                                "/api/auth/recuperar/solicitar", // enviar codigo al correo
                                "/api/auth/recuperar/verificar", // verificar codigo recibido
                                "/api/auth/recuperar/cambiar",   // guardar nueva contrasena
                                "/swagger-ui/**",                // documentacion Swagger
                                "/v3/api-docs/**"
                        ).permitAll()
                        // Cualquier otra ruta requiere token JWT valido
                        .anyRequest().authenticated()
                )

                // Sin sesiones: cada peticion trae su propio token JWT
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // Responde 401 con JSON cuando el token es invalido o no se envio
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(puntoEntradaAutenticacion())
                )

                // Conecta Spring Security con la BD y BCrypt
                .authenticationProvider(proveedorAutenticacion())

                // El filtro JWT se ejecuta antes que el filtro de usuario/contrasena
                .addFilterBefore(filtroJWT, UsernamePasswordAuthenticationFilter.class)

                .build();
    }

    // Define que origenes, metodos y headers estan permitidos para CORS
    @Bean
    public CorsConfigurationSource configuracionCors() {
        CorsConfiguration config = new CorsConfiguration();

        // Solo Angular en local puede hacer peticiones al backend
        config.setAllowedOrigins(List.of(
                "http://localhost:4200",
                "http://127.0.0.1:4200",
                "http://localhost:4000"
        ));

        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        // Permite enviar el header Authorization con el token JWT
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    // Conecta Spring Security con la BD y BCrypt para verificar contrasenas
    @Bean
    public AuthenticationProvider proveedorAutenticacion() {
        DaoAuthenticationProvider proveedor = new DaoAuthenticationProvider();
        proveedor.setUserDetailsService(userDetailsService);
        proveedor.setPasswordEncoder(encoderContrasena());
        return proveedor;
    }

    // Permite que los servicios puedan verificar credenciales manualmente
    @Bean
    public AuthenticationManager gestorAutenticacion(
            AuthenticationConfiguration config
    ) throws Exception {
        return config.getAuthenticationManager();
    }

    // Responde 401 con JSON cuando el token es invalido o no se envio
    @Bean
    public AuthenticationEntryPoint puntoEntradaAutenticacion() {
        return (request, response, authException) -> {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"error\": \"Credenciales incorrectas\"}");
        };
    }

    // Usa BCrypt para encriptar y comparar contrasenas
    @Bean
    public PasswordEncoder encoderContrasena() {
        return new BCryptPasswordEncoder();
    }
}

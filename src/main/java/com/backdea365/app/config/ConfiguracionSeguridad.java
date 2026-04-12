package com.backdea365.app.config;

// -------------------------------------------------------------
// ConfiguracionSeguridad.java
// Define las reglas de seguridad de la aplicacion:
//   - Que rutas son publicas (solo el login)
//   - Que rutas requieren autenticacion (todo lo demas)
//   - Configura CORS para permitir peticiones desde Angular
//   - Registra el filtro JWT que valida el token en cada peticion
// -------------------------------------------------------------

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

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class ConfiguracionSeguridad {

    private final FiltroJWT filtroJWT;
    private final UserDetailsService userDetailsService;

    // -- CADENA DE FILTROS DE SEGURIDAD ------------------------
    // Configura que rutas son publicas y cuales requieren token JWT valido.
    @Bean
    public SecurityFilterChain cadenaFiltros(HttpSecurity http) throws Exception {
        return http
                // Desactivar CSRF: no es necesario con JWT stateless
                .csrf(csrf -> csrf.disable())

                // Activar CORS para permitir peticiones desde Angular
                .cors(cors -> cors.configurationSource(configuracionCors()))

                // Definir rutas publicas y protegidas
                .authorizeHttpRequests(auth -> auth
                        // Solo el login es publico, no requiere token
                        .requestMatchers(
                                "/api/auth/login",
                                "/swagger-ui/**",
                                "/v3/api-docs/**"
                        ).permitAll()

                        // Cualquier otra ruta requiere token JWT valido
                        .anyRequest().authenticated()
                )

                // Politica stateless: el servidor no guarda sesiones.
                // Cada peticion debe traer su propio token JWT.
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // Devolver 401 en vez de 403 cuando las credenciales son incorrectas
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(puntoEntradaAutenticacion())
                )

                // Registrar el proveedor que verifica usuario + BCrypt contra la BD
                .authenticationProvider(proveedorAutenticacion())

                // El filtro JWT se ejecuta antes del filtro de usuario/contrasena
                .addFilterBefore(filtroJWT, UsernamePasswordAuthenticationFilter.class)

                .build();
    }

    // -- CONFIGURACION CORS ------------------------------------
    // Permite que Angular en localhost:4200 haga peticiones al backend.
    // Sin esto el navegador bloquea las peticiones por politica de origen cruzado.
    @Bean
    public CorsConfigurationSource configuracionCors() {
        CorsConfiguration config = new CorsConfiguration();

        // Origenes permitidos (Angular en desarrollo)
        config.setAllowedOrigins(List.of(
                "http://localhost:4200",
                "http://localhost:4000"
        ));

        // Metodos HTTP permitidos
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));

        // Todos los headers permitidos
        config.setAllowedHeaders(List.of("*"));

        // Permitir envio del header Authorization con el token
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    // -- PROVEEDOR DE AUTENTICACION ----------------------------
    // Conecta Spring Security con la BD y el encoder BCrypt.
    // Se usa cuando el servicio de login llama a gestorAutenticacion.authenticate().
    @Bean
    public AuthenticationProvider proveedorAutenticacion() {
        DaoAuthenticationProvider proveedor = new DaoAuthenticationProvider();
        proveedor.setUserDetailsService(userDetailsService);
        proveedor.setPasswordEncoder(encoderContrasena());
        return proveedor;
    }

    // -- AUTHENTICATION MANAGER --------------------------------
    // Necesario para que ServicioAutenticacion pueda verificar credenciales.
    @Bean
    public AuthenticationManager gestorAutenticacion(
            AuthenticationConfiguration config
    ) throws Exception {
        return config.getAuthenticationManager();
    }

    // -- PUNTO DE ENTRADA DE AUTENTICACION --------------------
    // Devuelve 401 con mensaje JSON cuando las credenciales son incorrectas.
    // Sin esto Spring Security devuelve 403, confundiendo al frontend.
    @Bean
    public AuthenticationEntryPoint puntoEntradaAutenticacion() {
        return (request, response, authException) -> {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"error\": \"Credenciales incorrectas\"}");
        };
    }

    // -- ENCODER DE CONTRASENA ---------------------------------
    // Usa BCrypt para comparar la contrasena ingresada con el hash guardado en la BD.
    @Bean
    public PasswordEncoder encoderContrasena() {
        return new BCryptPasswordEncoder();
    }
}

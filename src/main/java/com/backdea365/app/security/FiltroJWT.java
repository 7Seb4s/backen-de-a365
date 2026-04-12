package com.backdea365.app.security;

// ─────────────────────────────────────────────────────────────
// FiltroJWT.java
// Intercepta cada petición HTTP antes de que llegue al controlador.
// Si el header Authorization tiene un token válido, autentica al usuario
// y Spring Security le permite continuar.
// Si no hay token o es inválido, la petición sigue sin autenticación
// (Spring Security la bloqueará si la ruta es protegida).
// ─────────────────────────────────────────────────────────────

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class FiltroJWT extends OncePerRequestFilter {

    private final UtilJWT utilJWT;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest peticion,
            HttpServletResponse respuesta,
            FilterChain cadena
    ) throws ServletException, IOException {

        // Leer el header Authorization de la petición
        final String headerAuth = peticion.getHeader("Authorization");

        // Si no hay header o no empieza con "Bearer ", dejamos pasar sin autenticar
        if (headerAuth == null || !headerAuth.startsWith("Bearer ")) {
            cadena.doFilter(peticion, respuesta);
            return;
        }

        // Extraer el token (quitando el prefijo "Bearer ")
        final String token = headerAuth.substring(7);

        // Validar el token y autenticar si es correcto
        if (utilJWT.esTokenValido(token)) {

            // Obtener el código del usuario desde el token
            String codigo = utilJWT.extraerCodigo(token);

            // Cargar los detalles del usuario desde la base de datos
            UserDetails userDetails = userDetailsService.loadUserByUsername(codigo);

            // Crear el objeto de autenticación para Spring Security
            UsernamePasswordAuthenticationToken autenticacion =
                    new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );

            // Registrar la autenticación en el contexto de seguridad
            SecurityContextHolder.getContext().setAuthentication(autenticacion);
        }

        // Continuar con la cadena de filtros
        cadena.doFilter(peticion, respuesta);
    }
}

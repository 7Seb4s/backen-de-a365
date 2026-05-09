package com.backdea365.app.security;

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

// Intercepta cada peticion HTTP y valida el token JWT del header Authorization
// Si el token es valido, autentica al usuario para que pueda acceder a rutas protegidas
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

        // Leer el header Authorization de la peticion
        final String headerAuth = peticion.getHeader("Authorization");

        // Si no hay header o no empieza con "Bearer ", dejamos pasar sin autenticar
        if (headerAuth == null || !headerAuth.startsWith("Bearer ")) {
            cadena.doFilter(peticion, respuesta);
            return;
        }

        // Extraer el token quitando el prefijo "Bearer "
        final String token = headerAuth.substring(7);

        // Validar el token: si es correcto autenticamos al usuario
        if (utilJWT.esTokenValido(token)) {

            // Obtener el codigo del usuario desde el payload del token
            String codigo = utilJWT.extraerCodigo(token);

            // Cargar los detalles del usuario desde la BD
            UserDetails userDetails = userDetailsService.loadUserByUsername(codigo);

            // Crear el objeto de autenticacion para Spring Security
            UsernamePasswordAuthenticationToken autenticacion =
                    new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );

            // Registrar la autenticacion en el contexto de seguridad
            SecurityContextHolder.getContext().setAuthentication(autenticacion);
        }

        // Continuar con la cadena de filtros
        cadena.doFilter(peticion, respuesta);
    }
}

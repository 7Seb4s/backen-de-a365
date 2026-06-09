package com.backdea365.app.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
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

        final String headerAuth = peticion.getHeader("Authorization");

        if (headerAuth == null || !headerAuth.startsWith("Bearer ")) {
            cadena.doFilter(peticion, respuesta);
            return;
        }

        try {
            final String token = headerAuth.substring(7);

            if (utilJWT.esTokenValido(token)) {
                String codigo = utilJWT.extraerCodigo(token);
                UserDetails userDetails = userDetailsService.loadUserByUsername(codigo);

                UsernamePasswordAuthenticationToken autenticacion =
                        new UsernamePasswordAuthenticationToken(
                                userDetails, null, userDetails.getAuthorities()
                        );

                autenticacion.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(peticion)
                );

                SecurityContextHolder.getContext().setAuthentication(autenticacion);
                log.debug("JWT válido para usuario: {} con roles: {}",
                        codigo, userDetails.getAuthorities());
            } else {
                log.warn("JWT inválido o expirado para: {}", peticion.getRequestURI());
            }
        } catch (Exception e) {
            log.error("Error procesando JWT para {}: {}", peticion.getRequestURI(), e.getMessage());
            // No lanzar excepción — dejar que el request continúe sin autenticación
            // y que Spring Security devuelva 401 limpiamente
        }

        cadena.doFilter(peticion, respuesta);
    }
}
package com.backdea365.app.logging;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Registra en el log cada petición HTTP que atiende la aplicación:
 * método, ruta, estado de la respuesta, tiempo que tardó, IP del cliente
 * y usuario autenticado. Así queda un historial de todas las acciones
 * que pasan en la web.
 *
 * Se ejecuta al final de la cadena (LOWEST_PRECEDENCE), después del filtro
 * de seguridad, para que el usuario autenticado ya esté disponible.
 */
@Slf4j
@Component
@Order(Ordered.LOWEST_PRECEDENCE)
public class FiltroRegistroPeticiones extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(
            HttpServletRequest peticion,
            HttpServletResponse respuesta,
            FilterChain cadena
    ) throws ServletException, IOException {

        long inicio = System.currentTimeMillis();

        try {
            cadena.doFilter(peticion, respuesta);
        } finally {
            long duracion = System.currentTimeMillis() - inicio;

            log.info("{} {}{} -> {} ({} ms) | usuario={} | ip={}",
                    peticion.getMethod(),
                    peticion.getRequestURI(),
                    peticion.getQueryString() != null ? "?" + peticion.getQueryString() : "",
                    respuesta.getStatus(),
                    duracion,
                    usuarioActual(),
                    ipCliente(peticion));
        }
    }

    private String usuarioActual() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || "anonymousUser".equals(auth.getPrincipal())) {
            return "anónimo";
        }
        return auth.getName();
    }

    private String ipCliente(HttpServletRequest peticion) {
        String forwarded = peticion.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return peticion.getRemoteAddr();
    }

    /** No registrar monitoreo ni documentación para no ensuciar el log. */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest peticion) {
        String ruta = peticion.getRequestURI();
        return ruta.startsWith("/actuator")
                || ruta.startsWith("/swagger")
                || ruta.startsWith("/v3/api-docs");
    }
}

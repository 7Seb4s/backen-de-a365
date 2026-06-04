package com.backdea365.app.controller;

import com.backdea365.app.dto.PerfilDTO;
import com.backdea365.app.security.ServicioDetalleUsuario;
import com.backdea365.app.service.ServicioPerfil;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

// Endpoints para que un usuario logueado vea y edite su propio perfil
// Tambien expone el cambio de contrasena estando autenticado
@RestController
@RequestMapping("/api/perfil")
@RequiredArgsConstructor
public class ControladorPerfil {

    private final ServicioPerfil servicioPerfil;
    private final ServicioDetalleUsuario servicioDetalleUsuario;

    // GET /api/perfil
    // Devuelve los datos del perfil del usuario logueado
    @GetMapping
    public ResponseEntity<PerfilDTO.PerfilResponse> obtener(
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        Integer idUsuario = servicioDetalleUsuario.obtenerIdPorCodigo(userDetails.getUsername());
        return ResponseEntity.ok(servicioPerfil.obtenerPerfil(idUsuario));
    }

    // PUT /api/perfil
    // Actualiza nombre, correo, direccion, telefono y DNI del usuario logueado
    @PutMapping
    public ResponseEntity<PerfilDTO.OperacionResponse> actualizar(
            @Valid @RequestBody PerfilDTO.ActualizarRequest req,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        Integer idUsuario = servicioDetalleUsuario.obtenerIdPorCodigo(userDetails.getUsername());
        return ResponseEntity.ok(servicioPerfil.actualizarPerfil(idUsuario, req));
    }

    // PUT /api/perfil/contrasena
    // Cambia la contrasena del usuario logueado (vista Configuracion -> Cambiar contrasena)
    // Requiere la contrasena actual + la nueva + la confirmacion
    @PutMapping("/contrasena")
    public ResponseEntity<PerfilDTO.OperacionResponse> cambiarContrasena(
            @Valid @RequestBody PerfilDTO.CambiarContrasenaRequest req,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        Integer idUsuario = servicioDetalleUsuario.obtenerIdPorCodigo(userDetails.getUsername());
        return ResponseEntity.ok(servicioPerfil.cambiarContrasena(idUsuario, req));
    }
}


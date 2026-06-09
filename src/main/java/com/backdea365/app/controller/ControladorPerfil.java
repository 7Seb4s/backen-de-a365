package com.backdea365.app.controller;

import com.backdea365.app.dto.PerfilDTO;
import com.backdea365.app.security.ServicioDetalleUsuario;
import com.backdea365.app.service.ServicioPerfil;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

// Endpoints para que un usuario logueado vea y edite su propio perfil
// Tambien expone el cambio de contrasena y la subida de foto de perfil
@RestController
@RequestMapping("/api/perfil")
@RequiredArgsConstructor
public class ControladorPerfil {

    private final ServicioPerfil servicioPerfil;
    private final ServicioDetalleUsuario servicioDetalleUsuario;

    // GET /api/perfil
    // Devuelve los datos del perfil del usuario logueado (incluye fotoUrl)
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

    // PUT /api/perfil/foto
    // Recibe multipart/form-data con campo "foto" (JPEG, PNG, WEBP o GIF, max 5 MB)
    // Guarda en disco y persiste la URL en usuario_detalle.foto_url
    @PutMapping(value = "/foto", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<PerfilDTO.FotoResponse> subirFoto(
            @RequestParam("foto") MultipartFile foto,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        Integer idUsuario = servicioDetalleUsuario.obtenerIdPorCodigo(userDetails.getUsername());
        return ResponseEntity.ok(servicioPerfil.subirFoto(idUsuario, foto));
    }

    // PUT /api/perfil/contrasena
    // Cambia la contrasena del usuario logueado
    @PutMapping("/contrasena")
    public ResponseEntity<PerfilDTO.OperacionResponse> cambiarContrasena(
            @Valid @RequestBody PerfilDTO.CambiarContrasenaRequest req,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        Integer idUsuario = servicioDetalleUsuario.obtenerIdPorCodigo(userDetails.getUsername());
        return ResponseEntity.ok(servicioPerfil.cambiarContrasena(idUsuario, req));
    }
}

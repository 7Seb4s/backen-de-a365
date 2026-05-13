package com.backdea365.app.controller;

import com.backdea365.app.dto.UsuarioDTO;
import com.backdea365.app.service.ServicioUsuario;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

// Endpoints para gestión de usuarios (solo ADMINISTRADOR y GERENTE)
// POST /api/usuarios/crear → crea un nuevo usuario con código autoincremental
@RestController
@RequestMapping("/api/usuarios")
@RequiredArgsConstructor
public class ControladorUsuario {

    private final ServicioUsuario servicioUsuario;

    // POST /api/usuarios/crear
    // Requiere token JWT válido (protegido por Spring Security)
    // Body: { nombreCompleto, apellidoCompleto, dni, telefono, correo, rol }
    // Responde: { id, codigo, nombreCompleto, rol, mensaje }
    @PostMapping("/crear")
    public ResponseEntity<UsuarioDTO.CrearResponse> crearUsuario(
            @Valid @RequestBody UsuarioDTO.CrearRequest peticion
    ) {
        UsuarioDTO.CrearResponse respuesta = servicioUsuario.crearUsuario(peticion);
        return ResponseEntity.status(HttpStatus.CREATED).body(respuesta);
    }
}

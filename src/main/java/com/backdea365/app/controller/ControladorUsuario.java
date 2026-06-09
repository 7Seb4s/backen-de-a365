package com.backdea365.app.controller;

import com.backdea365.app.dto.UsuarioDTO;
import com.backdea365.app.service.ServicioUsuario;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

// Endpoints para gestión de usuarios
// Requieren autenticación JWT; el listado y desactivar son solo para admin/gerente
@RestController
@RequestMapping("/api/usuarios")
@RequiredArgsConstructor
public class ControladorUsuario {

    private final ServicioUsuario servicioUsuario;

    // POST /api/usuarios/crear
    // Crea un nuevo usuario con código autoincremental según el rol
    // Solo para ADMINISTRADOR y GERENTE
    @PostMapping("/crear")
    public ResponseEntity<UsuarioDTO.CrearResponse> crearUsuario(
            @Valid @RequestBody UsuarioDTO.CrearRequest peticion
    ) {
        UsuarioDTO.CrearResponse respuesta = servicioUsuario.crearUsuario(peticion);
        return ResponseEntity.status(HttpStatus.CREATED).body(respuesta);
    }

    // GET /api/usuarios
    // Lista todos los usuarios activos para el panel de administración
    // Solo para ADMINISTRADOR y GERENTE
    @GetMapping
    public ResponseEntity<List<UsuarioDTO.PanelItem>> listarActivos() {
        return ResponseEntity.ok(servicioUsuario.listarActivos());
    }

    // GET /api/usuarios/eliminados
    // Lista todos los usuarios desactivados (historial de eliminados)
    // Solo para ADMINISTRADOR y GERENTE
    @GetMapping("/eliminados")
    public ResponseEntity<List<UsuarioDTO.PanelItem>> listarEliminados() {
        return ResponseEntity.ok(servicioUsuario.listarEliminados());
    }
}

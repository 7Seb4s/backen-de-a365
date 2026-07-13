package com.backdea365.app.controller;

import com.backdea365.app.dto.ReniecDTO;
import com.backdea365.app.dto.UsuarioDTO;
import com.backdea365.app.service.ServicioReniec;
import com.backdea365.app.service.ServicioUsuario;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

// Endpoints para gestión de usuarios
// Solo accesible para ADMINISTRADOR y GERENTE
@RestController
@RequestMapping("/api/usuarios")
@RequiredArgsConstructor
@PreAuthorize("hasAnyRole('ADMINISTRADOR', 'GERENTE')")
public class ControladorUsuario {

    private final ServicioUsuario servicioUsuario;
    private final ServicioReniec  servicioReniec;

    // GET /api/usuarios/dni/{numero}
    // Consulta RENIEC (Decolecta) y devuelve nombres y apellidos para autocompletar
    // el formulario de creación de usuario. Solo para ADMINISTRADOR y GERENTE.
    @GetMapping("/dni/{numero}")
    public ResponseEntity<ReniecDTO.Persona> consultarDni(@PathVariable String numero) {
        return ResponseEntity.ok(servicioReniec.consultarDni(numero));
    }

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

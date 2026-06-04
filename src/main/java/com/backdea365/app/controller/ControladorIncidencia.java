package com.backdea365.app.controller;

import com.backdea365.app.dto.IncidenciaDTO;
import com.backdea365.app.security.ServicioDetalleUsuario;
import com.backdea365.app.service.ServicioIncidencia;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

// Endpoints REST para incidencias del usuario logueado
@RestController
@RequestMapping("/api/incidencias")
@RequiredArgsConstructor
public class ControladorIncidencia {

    private final ServicioIncidencia servicioIncidencia;
    private final ServicioDetalleUsuario servicioDetalleUsuario;

    // GET /api/incidencias
    // Lista las incidencias reportadas por el usuario logueado
    @GetMapping
    public ResponseEntity<List<IncidenciaDTO.ItemResumen>> listar(
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        Integer idUsuario = servicioDetalleUsuario.obtenerIdPorCodigo(userDetails.getUsername());
        return ResponseEntity.ok(servicioIncidencia.listar(idUsuario));
    }

    // POST /api/incidencias
    // Crea una nueva incidencia desde el formulario "Nueva incidencia"
    // Requiere asunto, tipo, numero_ticket (FK obligatoria) y contenido
    @PostMapping
    public ResponseEntity<IncidenciaDTO.OperacionResponse> crear(
            @Valid @RequestBody IncidenciaDTO.CrearRequest req,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        Integer idUsuario = servicioDetalleUsuario.obtenerIdPorCodigo(userDetails.getUsername());
        IncidenciaDTO.OperacionResponse resp = servicioIncidencia.crear(req, idUsuario);
        return ResponseEntity.status(HttpStatus.CREATED).body(resp);
    }

    // GET /api/incidencias/{id}
    // Devuelve el detalle completo de una incidencia (boton "Revisar")
    @GetMapping("/{id}")
    public ResponseEntity<IncidenciaDTO.DetalleResponse> detalle(@PathVariable Long id) {
        return ResponseEntity.ok(servicioIncidencia.obtenerDetalle(id));
    }
}


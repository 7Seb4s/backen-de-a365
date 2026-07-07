package com.backdea365.app.controller;

import com.backdea365.app.dto.TecnicoDTO;
import com.backdea365.app.service.ServicioTecnico;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

// Endpoints exclusivos para el TECNICO (rol GERENTE)
// Todos requieren autenticación (token JWT en header Authorization)
//
// ── Tickets ────────────────────────────────────────────────────
// GET  /api/tecnico/tickets?texto=
// PUT  /api/tecnico/tickets/{id}/aprobar
//
// ── Incidencias ────────────────────────────────────────────────
// GET  /api/tecnico/incidencias?texto=
// PUT  /api/tecnico/incidencias/{id}/asignar
@RestController
@RequestMapping("/api/tecnico")
@RequiredArgsConstructor
@PreAuthorize("hasRole('GERENTE')")
public class ControladorTecnico {

    private final ServicioTecnico servicioTecnico;

    // ═══════════════════════════════════════════════════
    //  TICKETS
    // ═══════════════════════════════════════════════════

    // GET /api/tecnico/tickets?texto=
    // Lista los tickets pendientes de aprobación con todos sus detalles
    @GetMapping("/tickets")
    public ResponseEntity<List<TecnicoDTO.TicketItem>> listarTickets(
            @RequestParam(required = false) String texto
    ) {
        return ResponseEntity.ok(servicioTecnico.listarTickets(texto));
    }

    // PUT /api/tecnico/tickets/{id}/aprobar
    // Aprueba un ticket (id = numero_ticket); pasa a EN_PROCESO_ATENCION
    @PutMapping("/tickets/{id}/aprobar")
    public ResponseEntity<TecnicoDTO.OperacionResponse> aprobarTicket(
            @PathVariable Integer id
    ) {
        return ResponseEntity.ok(servicioTecnico.aprobarTicket(id));
    }

    // PUT /api/tecnico/tickets/{id}/rechazar
    // Rechaza un ticket (id = numero_ticket); pasa a CANCELADO
    @PutMapping("/tickets/{id}/rechazar")
    public ResponseEntity<TecnicoDTO.OperacionResponse> rechazarTicket(
            @PathVariable Integer id
    ) {
        return ResponseEntity.ok(servicioTecnico.rechazarTicket(id));
    }

    // ═══════════════════════════════════════════════════
    //  INCIDENCIAS
    // ═══════════════════════════════════════════════════

    // GET /api/tecnico/incidencias?texto=
    // Lista las incidencias con todos sus detalles
    @GetMapping("/incidencias")
    public ResponseEntity<List<TecnicoDTO.IncidenciaItem>> listarIncidencias(
            @RequestParam(required = false) String texto
    ) {
        return ResponseEntity.ok(servicioTecnico.listarIncidencias(texto));
    }

    // PUT /api/tecnico/incidencias/{id}/asignar
    // Asigna/deriva una incidencia; pasa a EN_REVISION y guarda el área
    // Body: { "derivacion": "Area de Tecnologia" }
    @PutMapping("/incidencias/{id}/asignar")
    public ResponseEntity<TecnicoDTO.OperacionResponse> asignarIncidencia(
            @PathVariable Long id,
            @RequestBody  TecnicoDTO.AsignarRequest req
    ) {
        return ResponseEntity.ok(servicioTecnico.asignarIncidencia(id, req));
    }

    // PUT /api/tecnico/incidencias/{id}/rechazar
    // Rechaza una incidencia; pasa a RECHAZADA
    @PutMapping("/incidencias/{id}/rechazar")
    public ResponseEntity<TecnicoDTO.OperacionResponse> rechazarIncidencia(
            @PathVariable Long id
    ) {
        return ResponseEntity.ok(servicioTecnico.rechazarIncidencia(id));
    }
}

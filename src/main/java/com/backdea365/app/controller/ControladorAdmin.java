package com.backdea365.app.controller;

import com.backdena365.app.dto.AdminDTO;
import com.backdea365.app.security.ServicioDetalleUsuario;
import com.backdea365.app.service.ServicioAdmin;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.List;

// Endpoints exclusivos para ADMINISTRADOR y GERENTE
// Todos requieren autenticación (token JWT en header Authorization)
//
// ── Tablero kanban ─────────────────────────────────────────────
// GET  /api/admin/tablero?columna=EN_REVISION&texto=
// GET  /api/admin/tickets/{numero}/modal
// PUT  /api/admin/tickets/{numero}/mover
//
// ── Detalle completo de un ticket ──────────────────────────────
// GET  /api/admin/tickets?texto=&fecha=
// GET  /api/admin/tickets/{numero}
// GET  /api/admin/tickets/{numero}/mensajes
// POST /api/admin/tickets/{numero}/mensajes
// GET  /api/admin/tickets/{numero}/adjuntos
// POST /api/admin/tickets
//
// ── Gestión de usuarios ────────────────────────────────────────
// GET  /api/admin/usuarios/{id}/revision
// PUT  /api/admin/usuarios/{id}/desactivar
// PUT  /api/admin/usuarios/{id}/activar
// PUT  /api/admin/usuarios/{id}/rol
//
// ── Gráficos del dashboard ─────────────────────────────────────
// GET  /api/admin/dashboard/tickets-mes?anio=&mes=
// GET  /api/admin/dashboard/incidencias-semana
// GET  /api/admin/dashboard/tickets-semana
@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
public class ControladorAdmin {

    private final ServicioAdmin          servicioAdmin;
    private final ServicioDetalleUsuario servicioDetalleUsuario;

    // ═══════════════════════════════════════════════════
    //  TABLERO KANBAN
    // ═══════════════════════════════════════════════════

    // GET /api/admin/tablero?columna=EN_REVISION&texto=
    // Devuelve los tickets de una columna del kanban con filtro de texto opcional
    // columna: EN_REVISION | EN_PROCESO_ATENCION | COMPLETADO
    @GetMapping("/tablero")
    public ResponseEntity<List<AdminDTO.TableroTicketItem>> tablero(
            @RequestParam(defaultValue = "EN_REVISION") String columna,
            @RequestParam(required = false)             String texto
    ) {
        return ResponseEntity.ok(servicioAdmin.obtenerColumnaTablero(columna, texto));
    }

    // GET /api/admin/tickets/{numero}/modal
    // Vista rápida de un ticket para el modal del tablero (sin mensajes ni adjuntos)
    @GetMapping("/tickets/{numero}/modal")
    public ResponseEntity<AdminDTO.TicketDetalle> modalTicket(
            @PathVariable Integer numero
    ) {
        return ResponseEntity.ok(servicioAdmin.obtenerModalTicket(numero));
    }

    // PUT /api/admin/tickets/{numero}/mover
    // Mueve un ticket entre columnas del kanban actualizando estado y subestado
    // Body: { "columna": "EN_REVISION" | "EN_PROCESO_ATENCION" | "COMPLETADO" }
    @PutMapping("/tickets/{numero}/mover")
    public ResponseEntity<AdminDTO.OperacionResponse> moverTicket(
            @PathVariable Integer numero,
            @RequestBody  AdminDTO.MoverTicketRequest req
    ) {
        return ResponseEntity.ok(servicioAdmin.moverTicket(numero, req));
    }

    // ═══════════════════════════════════════════════════
    //  GESTIÓN DE TICKETS
    // ═══════════════════════════════════════════════════

    // GET /api/admin/tickets?texto=&fecha=2026-05-01
    // Busca tickets por texto libre (asunto, número, solicitante) y/o fecha
    // Si no se pasan parámetros devuelve todos los tickets ordenados por fecha
    @GetMapping("/tickets")
    public ResponseEntity<List<AdminDTO.TicketListaItem>> buscarTickets(
            @RequestParam(required = false) String texto,
            @RequestParam(required = false) String fecha
    ) {
        return ResponseEntity.ok(servicioAdmin.buscarTickets(texto, fecha));
    }

    // GET /api/admin/tickets/{numero}
    // Detalle completo de un ticket (para la pantalla de revisión del admin)
    @GetMapping("/tickets/{numero}")
    public ResponseEntity<AdminDTO.TicketDetalle> detalleTicket(
            @PathVariable Integer numero
    ) {
        return ResponseEntity.ok(servicioAdmin.obtenerDetalleTicket(numero));
    }

    // GET /api/admin/tickets/{numero}/mensajes
    // Hilo de mensajes de un ticket ordenado cronológicamente
    @GetMapping("/tickets/{numero}/mensajes")
    public ResponseEntity<List<AdminDTO.TicketMensaje>> mensajes(
            @PathVariable Integer numero
    ) {
        return ResponseEntity.ok(servicioAdmin.obtenerMensajes(numero));
    }

    // POST /api/admin/tickets/{numero}/mensajes
    // Envía un mensaje en el hilo de un ticket; el remitente es el usuario logueado
    @PostMapping("/tickets/{numero}/mensajes")
    public ResponseEntity<AdminDTO.OperacionResponse> enviarMensaje(
            @PathVariable Integer numero,
            @RequestBody  AdminDTO.EnviarMensajeRequest req,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        Integer idRemitente = servicioDetalleUsuario.obtenerIdPorCodigo(userDetails.getUsername());
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(servicioAdmin.enviarMensaje(numero, idRemitente, req));
    }

    // GET /api/admin/tickets/{numero}/adjuntos
    // Lista los archivos adjuntos de un ticket
    @GetMapping("/tickets/{numero}/adjuntos")
    public ResponseEntity<List<AdminDTO.TicketAdjunto>> adjuntos(
            @PathVariable Integer numero
    ) {
        return ResponseEntity.ok(servicioAdmin.obtenerAdjuntos(numero));
    }

    // POST /api/admin/tickets
    // Crea un ticket directamente desde el panel del admin
    @PostMapping("/tickets")
    public ResponseEntity<AdminDTO.OperacionResponse> crearTicket(
            @RequestBody AdminDTO.CrearTicketAdminRequest req
    ) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(servicioAdmin.crearTicketAdmin(req));
    }

    // ═══════════════════════════════════════════════════
    //  GESTIÓN DE USUARIOS
    // ═══════════════════════════════════════════════════

    // GET /api/admin/usuarios/{id}/revision
    // Devuelve el perfil completo del usuario con estadísticas de tickets
    @GetMapping("/usuarios/{id}/revision")
    public ResponseEntity<AdminDTO.RevisionUsuario> revisionUsuario(
            @PathVariable Integer id
    ) {
        return ResponseEntity.ok(servicioAdmin.revisarUsuario(id));
    }

    // PUT /api/admin/usuarios/{id}/desactivar
    // Desactiva (soft delete) un usuario — no lo elimina de la BD
    @PutMapping("/usuarios/{id}/desactivar")
    public ResponseEntity<AdminDTO.OperacionResponse> desactivarUsuario(
            @PathVariable Integer id
    ) {
        return ResponseEntity.ok(servicioAdmin.desactivarUsuario(id));
    }

    // PUT /api/admin/usuarios/{id}/activar
    // Reactiva un usuario previamente desactivado
    @PutMapping("/usuarios/{id}/activar")
    public ResponseEntity<AdminDTO.OperacionResponse> activarUsuario(
            @PathVariable Integer id
    ) {
        return ResponseEntity.ok(servicioAdmin.activarUsuario(id));
    }

    // PUT /api/admin/usuarios/{id}/rol
    // Cambia el rol de un usuario
    // Body: { "rol": "EMPLEADO" | "ADMINISTRADOR" | "GERENTE" }
    @PutMapping("/usuarios/{id}/rol")
    public ResponseEntity<AdminDTO.OperacionResponse> cambiarRol(
            @PathVariable Integer id,
            @RequestBody  AdminDTO.CambiarRolRequest req
    ) {
        return ResponseEntity.ok(servicioAdmin.cambiarRol(id, req));
    }

    // ═══════════════════════════════════════════════════
    //  GRÁFICOS DEL DASHBOARD
    // ═══════════════════════════════════════════════════

    // GET /api/admin/dashboard/tickets-mes?anio=2026&mes=5
    // Devuelve el resumen de tickets del mes para el reporte principal del dashboard
    // Si no se pasan parámetros usa el mes actual
    @GetMapping("/dashboard/tickets-mes")
    public ResponseEntity<AdminDTO.ResumenTicketsMes> resumenTicketsMes(
            @RequestParam(required = false) Integer anio,
            @RequestParam(required = false) Integer mes
    ) {
        LocalDate hoy = LocalDate.now();
        int a = anio != null ? anio : hoy.getYear();
        int m = mes  != null ? mes  : hoy.getMonthValue();
        return ResponseEntity.ok(servicioAdmin.obtenerResumenTicketsMes(a, m));
    }

    // GET /api/admin/dashboard/incidencias-semana
    // Devuelve el resumen de incidencias de la semana actual para el gráfico de torta
    @GetMapping("/dashboard/incidencias-semana")
    public ResponseEntity<AdminDTO.ResumenIncidenciasSemana> resumenIncidenciasSemana() {
        return ResponseEntity.ok(servicioAdmin.obtenerResumenIncidenciasSemana());
    }

    // GET /api/admin/dashboard/tickets-semana
    // Devuelve el resumen de tickets de la semana actual para el gráfico de dona
    @GetMapping("/dashboard/tickets-semana")
    public ResponseEntity<AdminDTO.ResumenTicketsSemana> resumenTicketsSemana() {
        return ResponseEntity.ok(servicioAdmin.obtenerResumenTicketsSemana());
    }
}

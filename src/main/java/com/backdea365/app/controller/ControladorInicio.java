package com.backdea365.app.controller;

import com.backdena365.app.dto.InicioDTO;
import com.backdea365.app.security.ServicioDetalleUsuario;
import com.backdea365.app.service.ServicioInicio;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.List;

// Endpoints para la pantalla de inicio del agente
// Todos requieren autenticación (token JWT en header Authorization)
@RestController
@RequestMapping("/api/inicio")
@RequiredArgsConstructor
public class ControladorInicio {

    private final ServicioInicio    servicioInicio;
    private final ServicioDetalleUsuario servicioDetalleUsuario;

    // GET /api/inicio/resumen
    // Devuelve el conteo de tickets pendientes, atendidos y cancelados del usuario
    @GetMapping("/resumen")
    public ResponseEntity<InicioDTO.ResumenTickets> resumen(
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        Integer idUsuario = servicioDetalleUsuario.obtenerIdPorCodigo(userDetails.getUsername());
        return ResponseEntity.ok(servicioInicio.obtenerResumen(idUsuario));
    }

    // GET /api/inicio/ticket-activo
    // Devuelve el ticket pendiente más reciente del usuario; null si no tiene ninguno
    @GetMapping("/ticket-activo")
    public ResponseEntity<InicioDTO.TicketActivo> ticketActivo(
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        Integer idUsuario = servicioDetalleUsuario.obtenerIdPorCodigo(userDetails.getUsername());
        return ResponseEntity.ok(servicioInicio.obtenerTicketActivo(idUsuario));
    }

    // GET /api/inicio/actividad/{idTicket}
    // Devuelve las últimas 10 acciones registradas en el ticket indicado
    @GetMapping("/actividad/{idTicket}")
    public ResponseEntity<List<InicioDTO.ActividadItem>> actividad(
            @PathVariable Long idTicket
    ) {
        return ResponseEntity.ok(servicioInicio.obtenerActividad(idTicket));
    }

    // GET /api/inicio/calendario?anio=2026&mes=5
    // Devuelve los días del mes que tienen tickets registrados para el usuario
    // Si no se pasan los parámetros usa el mes actual
    @GetMapping("/calendario")
    public ResponseEntity<List<InicioDTO.CalendarioDia>> calendario(
            @RequestParam(required = false) Integer anio,
            @RequestParam(required = false) Integer mes,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        Integer idUsuario = servicioDetalleUsuario.obtenerIdPorCodigo(userDetails.getUsername());
        LocalDate hoy = LocalDate.now();
        int a = anio != null ? anio : hoy.getYear();
        int m = mes  != null ? mes  : hoy.getMonthValue();
        return ResponseEntity.ok(servicioInicio.obtenerCalendario(idUsuario, a, m));
    }
}

package com.backdea365.app.controller;

import com.backdea365.app.dto.TicketDTO;
import com.backdea365.app.security.ServicioDetalleUsuario;
import com.backdea365.app.service.ServicioTicket;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

// Endpoints REST para tickets del usuario logueado
// Todos requieren autenticacion (token JWT en header Authorization)
@RestController
@RequestMapping("/api/tickets")
@RequiredArgsConstructor
public class ControladorTicket {

    private final ServicioTicket servicioTicket;
    private final ServicioDetalleUsuario servicioDetalleUsuario;

    // GET /api/tickets?tab=pendientes
    // Lista los tickets del usuario logueado segun el tab activo (pendientes/completados/cancelados)
    @GetMapping
    public ResponseEntity<List<TicketDTO.ItemResumen>> listar(
            @RequestParam(defaultValue = "pendientes") String tab,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        Integer idUsuario = servicioDetalleUsuario.obtenerIdPorCodigo(userDetails.getUsername());
        return ResponseEntity.ok(servicioTicket.listarPorTab(tab, idUsuario));
    }

    // GET /api/tickets/{numero}
    // Devuelve el detalle completo del ticket para mostrar en el modal "Estado del ticket"
    // El parametro es el numero_ticket (no el id interno)
    @GetMapping("/{numero}")
    public ResponseEntity<TicketDTO.DetalleResponse> detalle(
            @PathVariable Integer numero,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        Integer idUsuario = servicioDetalleUsuario.obtenerIdPorCodigo(userDetails.getUsername());
        boolean puedeVerTodo = tieneRolAdministrativo(userDetails);
        return ResponseEntity.ok(servicioTicket.obtenerDetalle(numero, idUsuario, puedeVerTodo));
    }

    // Un ADMINISTRADOR o GERENTE puede ver el detalle de cualquier ticket;
    // un EMPLEADO solo los suyos.
    private boolean tieneRolAdministrativo(UserDetails userDetails) {
        return userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(r -> r.equals("ROLE_ADMINISTRADOR") || r.equals("ROLE_GERENTE"));
    }

    // POST /api/tickets
    // Crea un nuevo ticket para el usuario logueado
    @PostMapping
    public ResponseEntity<TicketDTO.ItemResumen> crear(
            @RequestBody @Valid TicketDTO.CrearRequest req,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        Integer idUsuario = servicioDetalleUsuario.obtenerIdPorCodigo(userDetails.getUsername());
        return ResponseEntity.status(HttpStatus.CREATED).body(servicioTicket.crear(req, idUsuario));
    }
}
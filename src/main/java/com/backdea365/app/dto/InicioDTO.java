package com.backdea365.app.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

// DTOs para la pantalla de inicio del agente
// Alineados con sp_inicio_resumen_tickets, sp_inicio_ticket_activo,
// sp_inicio_actividad_ticket y sp_inicio_calendario_tickets_mes
public class InicioDTO {

    // ── Resumen de tickets del usuario logueado ──
    // Coincide con lo que devuelve sp_inicio_resumen_tickets
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ResumenTickets {
        private Integer ticketsPendientes;
        private Integer ticketsAtendidos;
        private Integer ticketsCancelados;
    }

    // ── Ticket activo más reciente del usuario ──
    // Coincide con sp_inicio_ticket_activo
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TicketActivo {
        private Long    idTicket;
        private Integer numeroTicket;
        private String  tipoTicket;
        private String  prioridad;
        private String  estado;
        private String  codigoAsignado;
    }

    // ── Ítem de actividad reciente de un ticket ──
    // Coincide con sp_inicio_actividad_ticket
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ActividadItem {
        private String descripcion;
        private String creadoEn;   // ISO string
    }

    // ── Ítem del calendario: días con tickets en el mes ──
    // Coincide con sp_inicio_calendario_tickets_mes
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CalendarioDia {
        private String  dia;       // "2026-05-12"
        private Integer cantidad;
    }
}

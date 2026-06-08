package com.backdea365.app.dto;

import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

// DTOs para listado y detalle de tickets
// Alineados con sp_tickets_listar y sp_ticket_mas_info de la BD
public class TicketDTO {

    // ── Item resumido para las cards de la vista Tickets ──
    // Refleja lo que devuelve sp_tickets_listar: numero, subestado, locacion
    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class ItemResumen {
        private Integer numero;        // numero_ticket
        private String  estado;        // subestado formateado para mostrar
        private String  locacion;      // locacion_area
        private Boolean resaltado;     // true si el subestado es EVALUACION_COMPLETADA
    }

    // ── Detalle completo para el modal "Estado del ticket" ──
    // Coincide con lo que retorna sp_ticket_mas_info + estadisticas del solicitante
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class DetalleResponse {
        // Datos del usuario solicitante
        private String usuarioNombre;
        private String usuarioPais;

        // Estadisticas globales del solicitante
        private Integer tickets;
        private Integer ticketsPendientes;
        private String  tiempoRespuesta;       // ej "20:00"
        private String  tiempoTotal;           // ej "1:13:43"

        // Detalles del usuario
        private String telefono;
        private String email;
        private String pais;
        private String plataforma;
        private String velocidadRespuesta;     // "Rapido" | "Normal" | "Lento"

        // Datos del ticket en cuestion
        private String ticketActivoId;         // ej "#1234556"
        private String tipoTicket;
        private String prioridad;
        private String asignadoA;              // codigo del agente
    }

    // ── Request para crear un nuevo ticket ──
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CrearRequest {
        @NotBlank private String asunto;
        @NotBlank private String locacion;
        private String descripcion;
        private String prioridad;
    }
}
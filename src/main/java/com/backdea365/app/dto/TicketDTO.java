package com.backdea365.app.dto;

import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

public class TicketDTO {

    // Refleja lo que devuelve sp_tickets_listar: numero, subestado, locacion
    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class ItemResumen {
        private Integer numero;
        private String  estado;
        private String  locacion;
        private Boolean resaltado;
    }

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
        private String  tiempoRespuesta;
        private String  tiempoTotal;

        // Detalles del usuario
        private String telefono;
        private String email;
        private String pais;
        private String plataforma;
        private String velocidadRespuesta;

        // Datos del ticket en cuestion
        private String ticketActivoId;
        private String tipoTicket;
        private String prioridad;
        private String asignadoA;
    }
}

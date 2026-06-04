package com.backdea365.app.dto;

import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

// DTOs para incidencias, alineados con sp_incidencias_listar, sp_incidencias_crear y sp_incidencias_detalle
public class IncidenciaDTO {

    // ── Item resumido para las cards de la lista de incidencias ──
    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class ItemResumen {
        private Long    id;          // id_incidencia
        private String  tipo;        // formateado: "Actualizacion"
        private String  tema;        // "Topic: <asunto>"
        private Boolean resaltado;   // true si es REPORTADA y tipo ACTUALIZACION
    }

    // ── Request para crear una nueva incidencia ──
    // numero_ticket es OBLIGATORIO en la BD (FK NOT NULL)
    @Data
    public static class CrearRequest {

        @NotBlank(message = "El asunto es obligatorio")
        @Size(max = 150, message = "El asunto no puede superar 150 caracteres")
        private String asunto;

        @NotBlank(message = "El tipo es obligatorio")
        @Size(max = 50)
        private String tipo;

        @NotNull(message = "El codigo del ticket es obligatorio")
        private Integer numeroTicket;       // referencia a tickets.numero_ticket

        @NotBlank(message = "El contenido es obligatorio")
        @Size(max = 5000, message = "El contenido no puede superar 5000 caracteres")
        private String contenido;
    }

    // ── Detalle completo de una incidencia (boton Revisar) ──
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class DetalleResponse {
        private Long    id;
        private String  asunto;
        private String  tipo;
        private String  contenido;
        private Integer numeroTicket;
        private String  estado;
        private String  fechaReporte;       // string ISO
        private String  codigoUsuario;
        private String  correoUsuario;
    }

    // ── Respuesta generica ──
    @Data
    @AllArgsConstructor
    public static class OperacionResponse {
        private String mensaje;
    }
}

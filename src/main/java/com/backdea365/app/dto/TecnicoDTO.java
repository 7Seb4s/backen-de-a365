package com.backdea365.app.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

// DTOs para la vista del TECNICO (rol GERENTE)
// Alineados con sp_tecnico_tickets_listar, sp_tecnico_ticket_aprobar,
// sp_tecnico_incidencias_listar, sp_tecnico_incidencia_asignar.
// Los nombres de campo coinciden exactamente con las interfaces del frontend
// (servicio-tecnico.ts) para que la data viaje sincronizada BD → backend → front.
public class TecnicoDTO {

    // ── Adjunto de un ticket / incidencia ──
    // Coincide con ticket_adjuntos (nombre_archivo, tamano_kb)
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Adjunto {
        private String nombre;   // nombre_archivo
        private String peso;     // "246kb" (formateado desde tamano_kb)
    }

    // ── Ticket que ve el tecnico (card + detalle en una sola carga) ──
    // Coincide con sp_tecnico_tickets_listar + adjuntos de la BD
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TicketItem {
        private Integer       id;             // numero_ticket (se usa para aprobar)
        private String        ticketId;       // "#56367"
        private String        codigoInterno;  // "ID-#4362" (desde id_ticket)
        private String        titulo;         // asunto
        private String        resumen;        // preview del contenido para la card
        private String        prioridad;      // Alto | Medio | Bajo
        private String        estado;         // pendiente | aprobado
        private String        remitente;      // nombre del solicitante
        private String        hora;           // "13:08 (hace 6 h)" desde creado_en
        private String        asunto;         // asunto
        private String        cuerpo;         // descripcion completa
        private List<Adjunto> adjuntos;
        private String        tipo;           // tipo_ticket
        private String        solicitadoPor;  // nombre del solicitante
        private String        asignadoA;      // nombre del asignado (o el tecnico)
    }

    // ── Incidencia que ve el tecnico (card + detalle en una sola carga) ──
    // Coincide con sp_tecnico_incidencias_listar
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class IncidenciaItem {
        private Long          id;             // id_incidencia (se usa para asignar)
        private String        incidenciaId;   // "#34754"
        private String        codigoInterno;  // "ID-#34754"
        private String        resumen;        // preview del contenido para la card
        private String        prioridad;      // Alto | Medio | Bajo
        private String        estado;         // pendiente | asignado
        private String        remitente;      // nombre del solicitante
        private String        hora;           // "13:08 (hace 6 h)" desde creado_en
        private String        asunto;         // asunto
        private String        cuerpo;         // contenido completo
        private List<Adjunto> adjuntos;
        private String        tipo;           // tipo de incidencia
        private String        solicitadoPor;  // nombre del solicitante
        private String        derivacion;     // area destino de la derivacion
    }

    // ── Request para asignar/derivar una incidencia ──
    // Usado por sp_tecnico_incidencia_asignar
    @Data
    public static class AsignarRequest {
        private String derivacion;   // "Area de Tecnologia", etc.
    }

    // ── Respuesta genérica de operaciones del tecnico ──
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class OperacionResponse {
        private String mensaje;
    }
}

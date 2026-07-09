package com.backdea365.app.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

// DTOs para las acciones de Editar / Eliminar / Adjuntos del admin.
public class AccionesAdminDTO {

    // ── Body para editar un ticket ──
    @Data
    public static class EditarTicketRequest {
        private String asunto;
        private String tipo;         // tipo_ticket
        private String prioridad;    // Alta/Media/Baja o ALTA/MEDIA/BAJA
        private String descripcion;
    }

    // ── Body para editar una incidencia ──
    @Data
    public static class EditarIncidenciaRequest {
        private String asunto;
        private String tipo;
        private String contenido;
    }

    // ── Respuesta al subir un adjunto ──
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AdjuntoResponse {
        private long   idAdjunto;
        private String nombreArchivo;
        private Integer tamanoKb;
        private String ruta;
        private String mensaje;
    }
}

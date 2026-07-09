package com.backdea365.app.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

// DTOs para la pantalla de Reportes del admin.
// Alineados con sp_admin_reportes_kpis y sp_admin_reportes_historial.
public class ReportesDTO {

    // ── KPIs (tarjetas superiores) ──
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Kpis {
        private int    totalResueltos;    // tickets ATENDIDO
        private int    totalPendientes;   // tickets PENDIENTE
        private int    totalIncidencias;  // todas las incidencias
        private String tiempoPromedio;    // "18 min" (creado → atendido)
    }

    // ── Fila del historial de tickets cerrados ──
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class HistorialItem {
        private String numero;        // "#123456"
        private String usuario;       // nombre del solicitante
        private String tipo;          // tipo_ticket
        private String estado;        // "Resuelto" | "Cancelado"
        private String estadoClase;   // "badge-verde" | "badge-rojo"
        private String fecha;         // "25/05/2026"
        private String tiempo;        // "12 min" | "—"
    }

    // ── Respuesta completa de /api/admin/reportes ──
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ReporteResponse {
        private Kpis                kpis;
        private List<HistorialItem> historial;
    }
}

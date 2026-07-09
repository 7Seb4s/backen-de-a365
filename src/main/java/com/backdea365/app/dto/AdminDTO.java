package com.backdea365.app.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

// DTOs para el panel de administración
// Alineados con sp_admin_tickets_listar, sp_admin_ticket_detalle,
// sp_admin_ticket_mensajes, sp_admin_ticket_enviar_mensaje,
// sp_admin_ticket_adjuntos, sp_admin_ticket_crear, sp_admin_ticket_mover,
// sp_admin_tablero_tickets, sp_admin_ticket_modal,
// sp_admin_revision_usuario, sp_admin_gestion_tickets_mes,
// sp_admin_incidencias_resumen_semana, sp_admin_tickets_resumen_semana,
// sp_desactivar_usuario, sp_activar_usuario, sp_cambiar_rol
public class AdminDTO {

    // ── Ítem del listado de tickets (buscador admin) ──
    // Coincide con sp_admin_tickets_listar
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TicketListaItem {
        private Long    idTicket;
        private Integer numeroTicket;
        private String  asunto;
        private String  prioridad;
        private String  estado;
        private String  subestado;
        private String  actualizadoEn;         // ISO string
        private String  solicitadoPor;          // nombre_completo del solicitante
        private String  previewUltimoMensaje;   // ultimo mensaje del ticket
    }

    // ── Detalle completo de un ticket para el modal del admin ──
    // Coincide con sp_admin_ticket_detalle y sp_admin_ticket_modal
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TicketDetalle {
        private Long    idTicket;
        private Integer numeroTicket;
        private String  asunto;
        private String  descripcion;
        private String  tipoTicket;
        private String  prioridad;
        private String  estado;
        private String  subestado;
        private String  locacionArea;
        private String  creadoEn;
        private String  actualizadoEn;
        private String  codigoSolicitante;
        private String  solicitadoPor;
        private String  codigoAsignado;
        private String  asignadoA;
    }

    // ── Mensaje del hilo de un ticket ──
    // Coincide con sp_admin_ticket_mensajes
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TicketMensaje {
        private Long   idMensaje;
        private String contenido;
        private String creadoEn;
        private String remitenteCodigo;
        private String remitenteNombre;
    }

    // ── Request para enviar un mensaje en un ticket ──
    // Usado por sp_admin_ticket_enviar_mensaje
    @Data
    public static class EnviarMensajeRequest {
        private String contenido;
    }

    // ── Adjunto de un ticket ──
    // Coincide con sp_admin_ticket_adjuntos
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TicketAdjunto {
        private Long    idAdjunto;
        private String  nombreArchivo;
        private Integer tamanoKb;
        private String  ruta;
        private String  creadoEn;
    }

    // ── Request para crear un ticket desde el panel admin ──
    // Usado por sp_admin_ticket_crear
    @Data
    public static class CrearTicketAdminRequest {
        private Integer numeroTicket;
        private String  asunto;
        private String  prioridad;          // ALTA | MEDIA | BAJA
        private String  tipoTicket;
        private Integer idSolicitante;
        private Integer idAsignado;
        private String  contenidoInicial;
    }

    // ── Request para mover un ticket en el tablero kanban ──
    // Usado por sp_admin_ticket_mover
    // columna: EN_REVISION | EN_PROCESO_ATENCION | COMPLETADO
    @Data
    public static class MoverTicketRequest {
        private String columna;
    }

    // ── Ítem del tablero kanban ──
    // Coincide con sp_admin_tablero_tickets
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TableroTicketItem {
        private Integer numeroTicket;
        private String  asunto;
        private String  actualizadoEn;
        private String  estado;
        private String  subestado;
        private String  previewUltimoMensaje;
        private Integer totalAdjuntos;
    }

    // ── Perfil completo de un usuario para la vista "Revisar" ──
    // Coincide con sp_admin_revision_usuario
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class RevisionUsuario {
        private String  nombreCompleto;
        private String  pais;
        private String  telefono;
        private String  correo;
        private String  locacion;
        private String  plataforma;
        private Integer ticketsTotal;
        private Integer ticketsPendientes;
        private String  tiempoRespuesta;        // HH:mm:ss
        private String  tiempoTotal;            // HH:mm:ss
        private Integer ticketActivoNumero;
        private String  ticketActivoTipo;
        private String  ticketActivoPrioridad;
        private String  asignadoCodigo;
        private String  asignadoNombre;
    }

    // ── Resumen mensual de tickets para el gráfico del dashboard ──
    // Coincide con sp_admin_gestion_tickets_mes
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ResumenTicketsMes {
        private Integer pendientes;
        private Integer cancelados;
        private Integer atendidos;
        private Integer total;
        private Integer pctPendientes;
        private Integer pctCancelados;
        private Integer pctAtendidos;
    }

    // ── Resumen semanal de incidencias para el gráfico de torta ──
    // Coincide con sp_admin_incidencias_resumen_semana
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ResumenIncidenciasSemana {
        private Integer reportadas;
        private Integer enRevision;
        private Integer resueltas;
        private Integer total;
    }

    // ── Resumen semanal de tickets para el gráfico de dona ──
    // Coincide con sp_admin_tickets_resumen_semana
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ResumenTicketsSemana {
        private Integer pendientes;
        private Integer atendidos;
        private Integer enProgreso;
        private Integer evaluando;
        private Integer total;
    }

    // ── Request para cambiar el rol de un usuario ──
    // Usado por sp_cambiar_rol
    @Data
    public static class CambiarRolRequest {
        private String rol;   // EMPLEADO | ADMINISTRADOR | GERENTE
    }

    // ── Respuesta genérica para operaciones del admin ──
    @Data
    @AllArgsConstructor
    public static class OperacionResponse {
        private String mensaje;
    }

    // ═══════════════════════════════════════════════════
    //  GESTIÓN DE INCIDENCIAS (admin)
    // ═══════════════════════════════════════════════════

    // ── Ítem de la lista de incidencias por tab ──
    // Coincide con IncidenciaAdminItem del frontend
    @Data
    @AllArgsConstructor
    public static class IncidenciaAdminItem {
        private Long    id;
        private String  tipo;
        private String  tema;
        private String  estado;
        private boolean resaltado;
        private String  solicitante;
        private String  fecha;
    }

    // ── Detalle completo de una incidencia para el modal ──
    // Coincide con IncidenciaAdminDetalle del frontend
    @Data
    @AllArgsConstructor
    public static class IncidenciaAdminDetalle {
        private Long    id;
        private String  tipo;
        private String  estado;
        private String  solicitante;
        private String  asignadaA;
        private String  fecha;
        private String  contenido;
        private Integer numeroTicket;
    }
}

package com.backdea365.app.service;

import com.backdea365.app.dto.TecnicoDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

// Lógica de negocio para la vista del TECNICO (rol GERENTE)
// Aprueba tickets y asigna/deriva incidencias.
// Librería: Apache Commons (StringUtils para validaciones null-safe de texto)
@Slf4j
@Service
@RequiredArgsConstructor
public class ServicioTecnico {

    private final JdbcTemplate jdbc;

    // ═══════════════════════════════════════════════════
    //  TICKETS
    // ═══════════════════════════════════════════════════

    // ── Listar tickets pendientes de aprobación ──
    // Llama a sp_tecnico_tickets_listar y adjunta los archivos de cada ticket
    public List<TecnicoDTO.TicketItem> listarTickets(String texto) {
        List<TecnicoDTO.TicketItem> tickets = jdbc.query(
                "CALL sp_tecnico_tickets_listar(?)",
                (rs, n) -> {
                    long   idTicket   = rs.getLong("id_ticket");
                    int    numero     = rs.getInt("numero_ticket");
                    String estado     = rs.getString("estado");
                    String subestado  = rs.getString("subestado");
                    String solicitante = rs.getString("solicitante");
                    String descripcion = StringUtils.trimToEmpty(rs.getString("descripcion"));

                    return new TecnicoDTO.TicketItem(
                            numero,                                  // id → numero_ticket (para aprobar)
                            "#" + numero,                            // ticketId
                            "ID-#" + idTicket,                       // codigoInterno
                            rs.getString("asunto"),                  // titulo
                            resumen(descripcion),                    // resumen (preview)
                            prioridadFront(rs.getString("prioridad")),
                            estadoTicketFront(estado, subestado),    // pendiente | aprobado | rechazado
                            solicitante,                             // remitente
                            formatearHora(rs.getTimestamp("creado_en")),
                            rs.getString("asunto"),                  // asunto
                            descripcion,                             // cuerpo
                            obtenerAdjuntos(idTicket),               // adjuntos reales de la BD
                            rs.getString("tipo_ticket"),             // tipo
                            solicitante,                             // solicitadoPor
                            StringUtils.defaultIfBlank(rs.getString("asignado"), "Sin asignar")
                    );
                },
                texto == null ? "" : texto.trim()
        );
        return tickets;
    }

    // ── Aprobar un ticket ──
    // Llama a sp_tecnico_ticket_aprobar; pasa el subestado a EN_PROCESO_ATENCION
    public TecnicoDTO.OperacionResponse aprobarTicket(Integer numeroTicket) {
        int filas = jdbc.update("CALL sp_tecnico_ticket_aprobar(?)", numeroTicket);
        if (filas == 0) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                    "Ticket no encontrado o ya no está pendiente");
        }
        log.info("Ticket #{} aprobado por el técnico", numeroTicket);
        return new TecnicoDTO.OperacionResponse("Ticket aprobado correctamente");
    }

    // ── Rechazar un ticket ──
    // Llama a sp_tecnico_ticket_rechazar; pasa el estado a CANCELADO
    public TecnicoDTO.OperacionResponse rechazarTicket(Integer numeroTicket) {
        int filas = jdbc.update("CALL sp_tecnico_ticket_rechazar(?)", numeroTicket);
        if (filas == 0) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Ticket no encontrado");
        }
        log.info("Ticket #{} rechazado por el técnico", numeroTicket);
        return new TecnicoDTO.OperacionResponse("Ticket rechazado correctamente");
    }

    // ═══════════════════════════════════════════════════
    //  INCIDENCIAS
    // ═══════════════════════════════════════════════════

    // ── Listar incidencias para asignar/derivar ──
    // Llama a sp_tecnico_incidencias_listar
    public List<TecnicoDTO.IncidenciaItem> listarIncidencias(String texto) {
        return jdbc.query(
                "CALL sp_tecnico_incidencias_listar(?)",
                (rs, n) -> {
                    long   id          = rs.getLong("id_incidencia");
                    String estado      = rs.getString("estado");
                    String solicitante = rs.getString("solicitante");
                    String contenido   = StringUtils.trimToEmpty(rs.getString("contenido"));

                    return new TecnicoDTO.IncidenciaItem(
                            id,                                      // id → id_incidencia (para asignar)
                            "#" + id,                                // incidenciaId
                            "ID-#" + id,                             // codigoInterno
                            resumen(contenido),                      // resumen (preview)
                            prioridadFront(rs.getString("prioridad")),
                            estadoIncidenciaFront(estado),           // pendiente | asignado
                            solicitante,                             // remitente
                            formatearHora(rs.getTimestamp("creado_en")),
                            rs.getString("asunto"),                  // asunto
                            contenido,                               // cuerpo
                            List.of(),                               // las incidencias no manejan adjuntos propios
                            StringUtils.capitalize(StringUtils.lowerCase(rs.getString("tipo"))),
                            solicitante,                             // solicitadoPor
                            StringUtils.defaultIfBlank(rs.getString("derivacion"), "Sin derivar")
                    );
                },
                texto == null ? "" : texto.trim()
        );
    }

    // ── Asignar/derivar una incidencia ──
    // Llama a sp_tecnico_incidencia_asignar; pasa el estado a EN_REVISION y guarda la derivación
    public TecnicoDTO.OperacionResponse asignarIncidencia(Long id, TecnicoDTO.AsignarRequest req) {
        String derivacion = StringUtils.trimToEmpty(req.getDerivacion());
        if (derivacion.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Debe indicar el área de derivación");
        }
        int filas = jdbc.update("CALL sp_tecnico_incidencia_asignar(?, ?)", id, derivacion);
        if (filas == 0) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Incidencia no encontrada");
        }
        log.info("Incidencia #{} asignada al {}", id, derivacion);
        return new TecnicoDTO.OperacionResponse("Incidencia asignada correctamente");
    }

    // ── Rechazar una incidencia ──
    // Llama a sp_tecnico_incidencia_rechazar; pasa el estado a RECHAZADA
    public TecnicoDTO.OperacionResponse rechazarIncidencia(Long id) {
        int filas = jdbc.update("CALL sp_tecnico_incidencia_rechazar(?)", id);
        if (filas == 0) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Incidencia no encontrada");
        }
        log.info("Incidencia #{} rechazada por el técnico", id);
        return new TecnicoDTO.OperacionResponse("Incidencia rechazada correctamente");
    }

    // ═══════════════════════════════════════════════════
    //  HELPERS PRIVADOS
    // ═══════════════════════════════════════════════════

    // ── Adjuntos reales de un ticket ──
    // Consulta directa a ticket_adjuntos; formatea el tamaño como "246kb"
    private List<TecnicoDTO.Adjunto> obtenerAdjuntos(long idTicket) {
        return jdbc.query(
                "SELECT nombre_archivo, tamano_kb FROM ticket_adjuntos WHERE id_ticket = ? ORDER BY id_adjunto",
                (rs, n) -> {
                    Integer kb = rs.getObject("tamano_kb", Integer.class);
                    return new TecnicoDTO.Adjunto(
                            rs.getString("nombre_archivo"),
                            (kb != null ? kb : 0) + "kb"
                    );
                },
                idTicket
        );
    }

    // Mapea la prioridad de la BD (ALTA/MEDIA/BAJA) al texto que muestra el front (Alto/Medio/Bajo)
    private String prioridadFront(String p) {
        if (p == null) return "Medio";
        return switch (p.toUpperCase()) {
            case "ALTA" -> "Alto";
            case "BAJA" -> "Bajo";
            default     -> "Medio";
        };
    }

    // Traduce estado + subestado del ticket al estado que espera el front
    // CANCELADO = rechazado; PENDIENTE+EN_REVISION = pendiente; resto = aprobado
    private String estadoTicketFront(String estado, String subestado) {
        if ("CANCELADO".equalsIgnoreCase(StringUtils.trimToEmpty(estado))) return "rechazado";
        return "EN_REVISION".equalsIgnoreCase(StringUtils.trimToEmpty(subestado))
                ? "pendiente" : "aprobado";
    }

    // Traduce el estado de la incidencia al estado que espera el front
    // REPORTADA = asignación pendiente; RECHAZADA = rechazada; resto = asignada
    private String estadoIncidenciaFront(String estado) {
        String e = StringUtils.upperCase(StringUtils.trimToEmpty(estado));
        if (e.equals("REPORTADA")) return "pendiente";
        if (e.equals("RECHAZADA")) return "rechazado";
        return "asignado";
    }

    // Corta el contenido para el preview de la card (máx 60 caracteres)
    private String resumen(String texto) {
        String limpio = StringUtils.normalizeSpace(StringUtils.trimToEmpty(texto));
        return limpio.length() > 60 ? limpio.substring(0, 60) + "..." : limpio;
    }

    // Formatea creado_en como "HH:mm (hace N h/d)" o "" si es null
    private String formatearHora(Timestamp ts) {
        if (ts == null) return "";
        LocalDateTime dt = ts.toLocalDateTime();
        String hora = dt.format(DateTimeFormatter.ofPattern("HH:mm"));
        long horas = Duration.between(dt, LocalDateTime.now()).toHours();

        String relativo;
        if (horas < 1)       relativo = "hace un momento";
        else if (horas < 24) relativo = "hace " + horas + " h";
        else                 relativo = "hace " + (horas / 24) + " d";

        return hora + " (" + relativo + ")";
    }
}

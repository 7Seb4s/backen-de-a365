package com.backdea365.app.service;

import com.backdena365.app.dto.InicioDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.sql.Timestamp;
import java.util.List;

// Lógica para la pantalla de inicio del agente
// Usa sp_inicio_resumen_tickets, sp_inicio_ticket_activo,
// sp_inicio_actividad_ticket y sp_inicio_calendario_tickets_mes
@Service
@RequiredArgsConstructor
public class ServicioInicio {

    private final JdbcTemplate jdbc;

    // ── Resumen de tickets del usuario logueado ──
    // Llama a sp_inicio_resumen_tickets para obtener conteos por estado
    public InicioDTO.ResumenTickets obtenerResumen(Integer idUsuario) {
        try {
            return jdbc.queryForObject(
                    "CALL sp_inicio_resumen_tickets(?)",
                    (rs, n) -> new InicioDTO.ResumenTickets(
                            rs.getInt("tickets_pendientes"),
                            rs.getInt("tickets_atendidos"),
                            rs.getInt("tickets_cancelados")
                    ),
                    idUsuario
            );
        } catch (Exception ex) {
            // Si el usuario no tiene tickets devuelve ceros en lugar de error
            return new InicioDTO.ResumenTickets(0, 0, 0);
        }
    }

    // ── Ticket activo más reciente del usuario ──
    // Llama a sp_inicio_ticket_activo; devuelve null si no hay ticket pendiente
    public InicioDTO.TicketActivo obtenerTicketActivo(Integer idUsuario) {
        List<InicioDTO.TicketActivo> filas = jdbc.query(
                "CALL sp_inicio_ticket_activo(?)",
                (rs, n) -> new InicioDTO.TicketActivo(
                        rs.getLong("id_ticket"),
                        rs.getInt("numero_ticket"),
                        rs.getString("tipo_ticket"),
                        rs.getString("prioridad"),
                        rs.getString("estado"),
                        rs.getString("codigo_asignado")
                ),
                idUsuario
        );
        return filas.isEmpty() ? null : filas.get(0);
    }

    // ── Actividad reciente de un ticket ──
    // Llama a sp_inicio_actividad_ticket; devuelve las últimas 10 acciones
    public List<InicioDTO.ActividadItem> obtenerActividad(Long idTicket) {
        return jdbc.query(
                "CALL sp_inicio_actividad_ticket(?)",
                (rs, n) -> {
                    Timestamp ts = rs.getTimestamp("creado_en");
                    return new InicioDTO.ActividadItem(
                            rs.getString("descripcion"),
                            ts != null ? ts.toLocalDateTime().toString() : ""
                    );
                },
                idTicket
        );
    }

    // ── Días con tickets en el mes para el mini-calendario ──
    // Llama a sp_inicio_calendario_tickets_mes con año y mes actuales si no se pasan
    public List<InicioDTO.CalendarioDia> obtenerCalendario(
            Integer idUsuario, Integer anio, Integer mes) {
        return jdbc.query(
                "CALL sp_inicio_calendario_tickets_mes(?, ?, ?)",
                (rs, n) -> new InicioDTO.CalendarioDia(
                        rs.getString("dia"),
                        rs.getInt("cantidad")
                ),
                idUsuario, anio, mes
        );
    }
}

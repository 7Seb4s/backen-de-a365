package com.backdea365.app.service;

import com.backdea365.app.dto.TicketDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.sql.Time;
import java.util.List;
import java.util.Map;

// Logica para listar y consultar tickets del usuario logueado
// Usa los stored procedures sp_tickets_listar y sp_ticket_mas_info
@Service
@RequiredArgsConstructor
public class ServicioTicket {

    private final JdbcTemplate jdbc;

    // ── Lista los tickets del usuario segun el tab activo ──
    // tab = "pendientes" | "completados" | "cancelados"
    // Internamente llama a sp_tickets_listar(id_usuario, pestaña)
    public List<TicketDTO.ItemResumen> listarPorTab(String tab, Integer idUsuario) {

        // Mapeo del tab del frontend al ENUM que espera el stored procedure
        String pestana = switch (tab.toLowerCase()) {
            case "pendientes"  -> "PENDIENTES";
            case "completados" -> "COMPLETADOS";
            case "cancelados"  -> "CANCELADOS";
            default            -> throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Tab invalido");
        };

        // Llamar al SP existente y mapear cada fila a ItemResumen
        return jdbc.query(
                "CALL sp_tickets_listar(?, ?)",
                (rs, n) -> {
                    String subestado = rs.getString("subestado");
                    boolean resaltado = "EVALUACION_COMPLETADA".equals(subestado);
                    return new TicketDTO.ItemResumen(
                            rs.getInt("numero_ticket"),
                            formatearSubestado(subestado),
                            rs.getString("locacion_area"),
                            resaltado
                    );
                },
                idUsuario, pestana
        );
    }

    // ── Detalle completo para el modal "Estado del ticket" ──
    // Usa sp_ticket_mas_info + 2 consultas extra para estadisticas globales del solicitante
    public TicketDTO.DetalleResponse obtenerDetalle(Integer numeroTicket) {

        Map<String, Object> fila;
        try {
            fila = jdbc.queryForMap("CALL sp_ticket_mas_info(?)", numeroTicket);
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Ticket no encontrado");
        }

        // Necesitamos el id del solicitante para las estadisticas (no viene en el SP)
        Integer idSolicitante = jdbc.queryForObject(
                "SELECT id_solicitante FROM tickets WHERE numero_ticket = ?",
                Integer.class, numeroTicket
        );

        Integer totalTickets = jdbc.queryForObject(
                "SELECT COUNT(*) FROM tickets WHERE id_solicitante = ?",
                Integer.class, idSolicitante
        );
        Integer totalPendientes = jdbc.queryForObject(
                "SELECT COUNT(*) FROM tickets WHERE id_solicitante = ? AND estado = 'PENDIENTE'",
                Integer.class, idSolicitante
        );

        // Construir el DTO con los datos del SP
        TicketDTO.DetalleResponse dto = new TicketDTO.DetalleResponse();
        dto.setUsuarioNombre((String) fila.get("nombre_completo"));
        dto.setUsuarioPais((String) fila.get("pais"));
        dto.setTickets(totalTickets);
        dto.setTicketsPendientes(totalPendientes);
        dto.setTiempoRespuesta(formatearTime((Time) fila.get("tiempo_respuesta")));
        dto.setTiempoTotal(formatearTime((Time) fila.get("tiempo_total")));
        dto.setTelefono((String) fila.get("telefono"));
        dto.setEmail((String) fila.get("correo"));
        dto.setPais((String) fila.get("pais"));
        dto.setPlataforma((String) fila.get("plataforma"));
        dto.setVelocidadRespuesta(clasificarVelocidad((Time) fila.get("tiempo_respuesta")));
        dto.setTicketActivoId("#" + fila.get("numero_ticket"));
        dto.setTipoTicket((String) fila.get("tipo_ticket"));
        dto.setPrioridad((String) fila.get("prioridad"));
        dto.setAsignadoA((String) fila.get("codigo_asignado"));

        return dto;
    }

    // ── Crea un nuevo ticket para el usuario logueado ──
    // Llama a sp_ticket_crear y retorna el item recien creado
    public TicketDTO.ItemResumen crear(TicketDTO.CrearRequest req, Integer idUsuario) {
        jdbc.update(
                "CALL sp_ticket_crear(?, ?, ?, ?, ?)",
                idUsuario, req.getAsunto(), req.getLocacion(), req.getDescripcion(), req.getPrioridad()
        );

        // Retorna el ultimo ticket creado por ese usuario
        return jdbc.queryForObject(
                "SELECT numero_ticket, subestado, locacion_area FROM tickets " +
                "WHERE id_solicitante = ? ORDER BY numero_ticket DESC LIMIT 1",
                (rs, n) -> new TicketDTO.ItemResumen(
                        rs.getInt("numero_ticket"),
                        formatearSubestado(rs.getString("subestado")),
                        rs.getString("locacion_area"),
                        false
                ),
                idUsuario
        );
    }

    // ── Helpers ──

    // Convierte EN_PROCESO -> "En proceso", EVALUACION_COMPLETADA -> "Evaluacion completada"
    private String formatearSubestado(String enumValue) {
        if (enumValue == null) return "";
        String txt = enumValue.replace("_", " ").toLowerCase();
        return Character.toUpperCase(txt.charAt(0)) + txt.substring(1);
    }

    // Convierte un java.sql.Time (HH:mm:ss) a "H:MM:SS" o "MM:SS"
    private String formatearTime(Time t) {
        if (t == null) return "0:00";
        return t.toString();
    }

    // Clasifica la velocidad de respuesta segun el tiempo
    // Hasta 15 min: Rapido, hasta 45 min: Normal, mas: Lento
    private String clasificarVelocidad(Time t) {
        if (t == null) return "Normal";
        long minutos = t.toLocalTime().toSecondOfDay() / 60;
        if (minutos <= 15) return "Rapido";
        if (minutos <= 45) return "Normal";
        return "Lento";
    }
}

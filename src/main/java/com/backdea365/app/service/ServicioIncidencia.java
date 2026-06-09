package com.backdea365.app.service;

import com.backdea365.app.dto.IncidenciaDTO;
import com.google.common.base.Preconditions;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

// Logica para incidencias del usuario logueado
// Usa sp_incidencias_listar, sp_incidencias_crear, sp_incidencias_detalle
@Service
@RequiredArgsConstructor
public class ServicioIncidencia {

    private final JdbcTemplate jdbc;

    // ── Listar incidencias del usuario logueado ──
    public List<IncidenciaDTO.ItemResumen> listar(Integer idUsuario) {

        return jdbc.query(
                "CALL sp_incidencias_listar(?)",
                (rs, n) -> {
                    String tipo   = rs.getString("tipo");
                    String estado = rs.getString("estado");
                    String asunto = rs.getString("asunto");
                    // Resaltado solo si esta REPORTADA y es de tipo ACTUALIZACION
                    boolean resaltado = "REPORTADA".equals(estado)
                                     && "ACTUALIZACION".equalsIgnoreCase(tipo);
                    return new IncidenciaDTO.ItemResumen(
                            rs.getLong("id_incidencia"),
                            capitalizar(tipo),
                            "Topic: " + asunto,
                            resaltado
                    );
                },
                idUsuario
        );
    }

    // ── Crear una nueva incidencia (vista "Nueva incidencia") ──
    // numero_ticket es FK NOT NULL, asi que debe existir en tickets
    public IncidenciaDTO.OperacionResponse crear(IncidenciaDTO.CrearRequest req, Integer idUsuario) {

        // Guava Preconditions: validación expresiva de parámetros
        Preconditions.checkArgument(
                StringUtils.isNotBlank(req.getAsunto()), "El asunto es obligatorio");
        Preconditions.checkArgument(
                StringUtils.isNotBlank(req.getTipo()), "El tipo es obligatorio");
        Preconditions.checkArgument(
                StringUtils.isNotBlank(req.getContenido()), "El contenido es obligatorio");
        Preconditions.checkNotNull(
                req.getNumeroTicket(), "El número de ticket es obligatorio");

        // Verificar que el ticket exista antes de crear la incidencia
        Integer existeTicket = jdbc.queryForObject(
                "SELECT COUNT(*) FROM tickets WHERE numero_ticket = ?",
                Integer.class, req.getNumeroTicket()
        );
        if (existeTicket == null || existeTicket == 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "El numero de ticket no existe");
        }

        try {
            jdbc.update(
                    "CALL sp_incidencias_crear(?, ?, ?, ?, ?)",
                    idUsuario,
                    StringUtils.trimToEmpty(req.getAsunto()),
                    StringUtils.trimToEmpty(req.getTipo()),
                    req.getNumeroTicket(),
                    StringUtils.trimToEmpty(req.getContenido())
            );
        } catch (DataAccessException ex) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Error al crear la incidencia");
        }

        return new IncidenciaDTO.OperacionResponse("Incidencia reportada exitosamente");
    }

    // ── Detalle de una incidencia (boton Revisar) ──
    public IncidenciaDTO.DetalleResponse obtenerDetalle(Long idIncidencia) {
        try {
            return jdbc.queryForObject(
                    "CALL sp_incidencias_detalle(?)",
                    (rs, n) -> new IncidenciaDTO.DetalleResponse(
                            rs.getLong("id_incidencia"),
                            rs.getString("asunto"),
                            rs.getString("tipo"),
                            rs.getString("contenido"),
                            rs.getInt("numero_ticket"),
                            rs.getString("estado"),
                            rs.getTimestamp("creado_en").toLocalDateTime().toString(),
                            rs.getString("codigo_usuario"),
                            rs.getString("correo")
                    ),
                    idIncidencia
            );
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Incidencia no encontrada");
        }
    }

    // Apache Commons: StringUtils.capitalize reemplaza el helper manual
    private String capitalizar(String s) {
        return StringUtils.capitalize(StringUtils.lowerCase(StringUtils.defaultString(s)));
    }
}

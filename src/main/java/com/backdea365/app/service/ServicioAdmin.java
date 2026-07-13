package com.backdea365.app.service;

import com.backdea365.app.dto.AdminDTO;
import com.backdea365.app.dto.ReportesDTO;
import com.backdea365.app.dto.AccionesAdminDTO;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.multipart.MultipartFile;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.UUID;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.sql.Time;
import java.sql.Timestamp;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

// Lógica de negocio para el panel de administración
// Librerías: Google Guava (CacheBuilder para cacheo del dashboard),
//            Apache Commons (StringUtils para validaciones de texto)
@Slf4j
@Service
@RequiredArgsConstructor
public class ServicioAdmin {

    private final JdbcTemplate jdbc;

    // ── Guava Cache: cachea el resumen semanal de incidencias por 5 minutos ──
    // Evita consultas repetidas a la BD cuando varios admins abren el dashboard
    private LoadingCache<String, AdminDTO.ResumenIncidenciasSemana> cacheIncidenciasSemana;
    private LoadingCache<String, AdminDTO.ResumenTicketsSemana>     cacheTicketsSemana;

    @jakarta.annotation.PostConstruct
    private void inicializarCaches() {
        this.cacheIncidenciasSemana = CacheBuilder.newBuilder()
                .maximumSize(1)
                .expireAfterWrite(5, TimeUnit.MINUTES)
                .build(CacheLoader.from(key -> cargarIncidenciasSemana()));

        this.cacheTicketsSemana = CacheBuilder.newBuilder()
                .maximumSize(1)
                .expireAfterWrite(5, TimeUnit.MINUTES)
                .build(CacheLoader.from(key -> cargarTicketsSemana()));

        log.info("Caches del dashboard inicializados (TTL: 5 min)");
    }

    // ═══════════════════════════════════════════════════
    //  TABLERO KANBAN DE TICKETS
    // ═══════════════════════════════════════════════════

    // ── Columna del tablero kanban ──
    // Llama a sp_admin_tablero_tickets filtrando por columna y texto de búsqueda
    // columna: EN_REVISION | EN_PROCESO_ATENCION | COMPLETADO
    public List<AdminDTO.TableroTicketItem> obtenerColumnaTablero(
            String columna, String texto) {
        return jdbc.query(
                "CALL sp_admin_tablero_tickets(?, ?)",
                (rs, n) -> new AdminDTO.TableroTicketItem(
                        rs.getInt("numero_ticket"),
                        rs.getString("asunto"),
                        timestampToString(rs.getTimestamp("actualizado_en")),
                        rs.getString("estado"),
                        rs.getString("subestado"),
                        rs.getString("preview_ultimo_mensaje"),
                        rs.getObject("total_adjuntos", Integer.class)
                ),
                columna,
                texto == null ? "" : texto.trim()
        );
    }

    // ── Modal de un ticket (vista rápida desde el tablero) ──
    // Llama a sp_admin_ticket_modal con el número de ticket
    public AdminDTO.TicketDetalle obtenerModalTicket(Integer numeroTicket) {
        List<AdminDTO.TicketDetalle> filas = jdbc.query(
                "CALL sp_admin_ticket_modal(?)",
                (rs, n) -> new AdminDTO.TicketDetalle(
                        null,
                        rs.getInt("numero_ticket"),
                        rs.getString("asunto"),
                        rs.getString("descripcion"),
                        rs.getString("tipo_ticket"),
                        rs.getString("prioridad"),
                        rs.getString("estado"),
                        rs.getString("subestado"),
                        null, null,
                        timestampToString(rs.getTimestamp("creado_en")),
                        null,
                        rs.getString("solicitante_nombre"),
                        rs.getString("asignado_codigo"),
                        rs.getString("asignado_nombre")
                ),
                numeroTicket
        );
        if (filas.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Ticket no encontrado");
        }
        return filas.get(0);
    }

    // ── Mover ticket entre columnas del kanban ──
    // Llama a sp_admin_ticket_mover; actualiza estado y subestado según columna
    public AdminDTO.OperacionResponse moverTicket(
            Integer numeroTicket, AdminDTO.MoverTicketRequest req) {

        // Apache Commons: normalización segura del input (null-safe)
        String columna = StringUtils.upperCase(StringUtils.trimToEmpty(req.getColumna()));
        if (!columna.equals("EN_REVISION")
                && !columna.equals("EN_PROCESO_ATENCION")
                && !columna.equals("COMPLETADO")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Columna inválida. Valores: EN_REVISION, EN_PROCESO_ATENCION, COMPLETADO");
        }

        jdbc.update("CALL sp_admin_ticket_mover(?, ?)", numeroTicket, columna);
        log.info("Ticket #{} movido a columna {}", numeroTicket, columna);
        return new AdminDTO.OperacionResponse("Ticket movido correctamente");
    }

    // ═══════════════════════════════════════════════════
    //  DETALLE COMPLETO DE UN TICKET
    // ═══════════════════════════════════════════════════

    // ── Detalle completo para la vista de revisión ──
    // Llama a sp_admin_ticket_detalle con el número de ticket
    public AdminDTO.TicketDetalle obtenerDetalleTicket(Integer numeroTicket) {
        List<AdminDTO.TicketDetalle> filas = jdbc.query(
                "CALL sp_admin_ticket_detalle(?)",
                (rs, n) -> new AdminDTO.TicketDetalle(
                        rs.getLong("id_ticket"),
                        rs.getInt("numero_ticket"),
                        rs.getString("asunto"),
                        null,
                        rs.getString("tipo_ticket"),
                        rs.getString("prioridad"),
                        rs.getString("estado"),
                        rs.getString("subestado"),
                        rs.getString("locacion_area"),
                        timestampToString(rs.getTimestamp("creado_en")),
                        timestampToString(rs.getTimestamp("actualizado_en")),
                        rs.getString("codigo_solicitante"),
                        rs.getString("solicitado_por"),
                        rs.getString("codigo_asignado"),
                        rs.getString("asignado_a")
                ),
                numeroTicket
        );
        if (filas.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Ticket no encontrado");
        }
        return filas.get(0);
    }

    // ── Mensajes del hilo de un ticket ──
    // Llama a sp_admin_ticket_mensajes ordenados cronológicamente
    public List<AdminDTO.TicketMensaje> obtenerMensajes(Integer numeroTicket) {
        return jdbc.query(
                "CALL sp_admin_ticket_mensajes(?)",
                (rs, n) -> new AdminDTO.TicketMensaje(
                        rs.getLong("id_mensaje"),
                        rs.getString("contenido"),
                        timestampToString(rs.getTimestamp("creado_en")),
                        rs.getString("remitente_codigo"),
                        rs.getString("remitente_nombre")
                ),
                numeroTicket
        );
    }

    // ── Enviar un mensaje en el hilo de un ticket ──
    // Llama a sp_admin_ticket_enviar_mensaje y actualiza actualizado_en del ticket
    public AdminDTO.OperacionResponse enviarMensaje(
            Integer numeroTicket, Integer idRemitente, AdminDTO.EnviarMensajeRequest req) {

        if (req.getContenido() == null || req.getContenido().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "El contenido del mensaje no puede estar vacío");
        }

        jdbc.update("CALL sp_admin_ticket_enviar_mensaje(?, ?, ?)",
                numeroTicket, idRemitente, req.getContenido().trim());

        log.info("Mensaje enviado en ticket #{} por usuario {}", numeroTicket, idRemitente);
        return new AdminDTO.OperacionResponse("Mensaje enviado correctamente");
    }

    // ── Adjuntos de un ticket ──
    // Llama a sp_admin_ticket_adjuntos con el número de ticket
    public List<AdminDTO.TicketAdjunto> obtenerAdjuntos(Integer numeroTicket) {
        return jdbc.query(
                "CALL sp_admin_ticket_adjuntos(?)",
                (rs, n) -> new AdminDTO.TicketAdjunto(
                        rs.getObject("id_adjunto", Long.class),
                        rs.getString("nombre_archivo"),
                        rs.getObject("tamano_kb", Integer.class),
                        rs.getString("ruta"),
                        timestampToString(rs.getTimestamp("creado_en"))
                ),
                numeroTicket
        );
    }

    // ── Buscar tickets (buscador del admin) ──
    // Llama a sp_admin_tickets_listar con texto libre y fecha opcional
    public List<AdminDTO.TicketListaItem> buscarTickets(String texto, String fecha) {
        // fecha puede ser null → el SP busca todos
        Object fechaParam = (fecha == null || fecha.isBlank()) ? null : java.sql.Date.valueOf(fecha);
        return jdbc.query(
                "CALL sp_admin_tickets_listar(?, ?)",
                (rs, n) -> new AdminDTO.TicketListaItem(
                        rs.getLong("id_ticket"),
                        rs.getInt("numero_ticket"),
                        rs.getString("asunto"),
                        rs.getString("prioridad"),
                        rs.getString("estado"),
                        rs.getString("subestado"),
                        timestampToString(rs.getTimestamp("actualizado_en")),
                        rs.getString("solicitado_por"),
                        rs.getString("preview_ultimo_mensaje")
                ),
                texto == null ? "" : texto.trim(),
                fechaParam
        );
    }

    // ── Crear un ticket desde el panel admin ──
    // Llama a sp_admin_ticket_crear con todos los campos necesarios
    public AdminDTO.OperacionResponse crearTicketAdmin(AdminDTO.CrearTicketAdminRequest req) {
        jdbc.update(
                "CALL sp_admin_ticket_crear(?, ?, ?, ?, ?, ?, ?)",
                req.getNumeroTicket(),
                req.getAsunto(),
                req.getPrioridad().toUpperCase(),
                req.getTipoTicket(),
                req.getIdSolicitante(),
                req.getIdAsignado(),
                req.getContenidoInicial()
        );
        log.info("Ticket admin creado: #{}", req.getNumeroTicket());
        return new AdminDTO.OperacionResponse("Ticket creado correctamente");
    }

    // ═══════════════════════════════════════════════════
    //  GESTIÓN DE USUARIOS
    // ═══════════════════════════════════════════════════

    // ── Perfil completo de un usuario para la vista "Revisar" ──
    // Llama a sp_admin_revision_usuario con el id del usuario
    public AdminDTO.RevisionUsuario revisarUsuario(Integer idUsuario) {
        List<AdminDTO.RevisionUsuario> filas = jdbc.query(
                "CALL sp_admin_revision_usuario(?)",
                (rs, n) -> new AdminDTO.RevisionUsuario(
                        rs.getString("nombre_completo"),
                        rs.getString("pais"),
                        rs.getString("telefono"),
                        rs.getString("correo"),
                        rs.getString("locacion"),
                        rs.getString("plataforma"),
                        rs.getInt("tickets_total"),
                        rs.getInt("tickets_pendientes"),
                        formatearTime(rs.getObject("tiempo_respuesta", Time.class)),
                        formatearTime(rs.getObject("tiempo_total", Time.class)),
                        rs.getObject("ticket_activo_numero", Integer.class),
                        rs.getString("ticket_activo_tipo"),
                        rs.getString("ticket_activo_prioridad"),
                        rs.getString("asignado_codigo"),
                        rs.getString("asignado_nombre")
                ),
                idUsuario
        );
        if (filas.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Usuario no encontrado");
        }
        return filas.get(0);
    }

    // ── Desactivar usuario (soft delete) ──
    // Llama a sp_desactivar_usuario; no borra de la BD
    public AdminDTO.OperacionResponse desactivarUsuario(Integer idUsuario) {
        jdbc.update("CALL sp_desactivar_usuario(?)", idUsuario);
        log.info("Usuario {} desactivado", idUsuario);
        return new AdminDTO.OperacionResponse("Usuario desactivado correctamente");
    }

    // ── Reactivar usuario ──
    // Llama a sp_activar_usuario
    public AdminDTO.OperacionResponse activarUsuario(Integer idUsuario) {
        jdbc.update("CALL sp_activar_usuario(?)", idUsuario);
        log.info("Usuario {} reactivado", idUsuario);
        return new AdminDTO.OperacionResponse("Usuario reactivado correctamente");
    }

    // ── Cambiar rol de un usuario ──
    // Llama a sp_cambiar_rol; valida que el rol sea uno de los tres permitidos
    public AdminDTO.OperacionResponse cambiarRol(
            Integer idUsuario, AdminDTO.CambiarRolRequest req) {

        // Apache Commons: normalización segura del input
        String rol = StringUtils.upperCase(StringUtils.trimToEmpty(req.getRol()));
        if (!rol.equals("EMPLEADO") && !rol.equals("ADMINISTRADOR") && !rol.equals("GERENTE")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Rol inválido. Valores: EMPLEADO, ADMINISTRADOR, GERENTE");
        }

        jdbc.update("CALL sp_cambiar_rol(?, ?)", idUsuario, rol);
        log.info("Rol de usuario {} cambiado a {}", idUsuario, rol);
        return new AdminDTO.OperacionResponse("Rol actualizado correctamente");
    }

    // ═══════════════════════════════════════════════════
    //  GRÁFICOS DEL DASHBOARD ADMIN
    // ═══════════════════════════════════════════════════

    // ── Resumen mensual de tickets para el reporte principal ──
    // Llama a sp_admin_gestion_tickets_mes con año y mes
    public AdminDTO.ResumenTicketsMes obtenerResumenTicketsMes(Integer anio, Integer mes) {
        List<AdminDTO.ResumenTicketsMes> filas = jdbc.query(
                "CALL sp_admin_gestion_tickets_mes(?, ?)",
                (rs, n) -> new AdminDTO.ResumenTicketsMes(
                        rs.getInt("pendientes"),
                        rs.getInt("cancelados"),
                        rs.getInt("atendidos"),
                        rs.getInt("total"),
                        rs.getInt("pct_pendientes"),
                        rs.getInt("pct_cancelados"),
                        rs.getInt("pct_atendidos")
                ),
                anio, mes
        );
        // Si no hay datos del mes devuelve ceros
        return filas.isEmpty()
                ? new AdminDTO.ResumenTicketsMes(0, 0, 0, 0, 0, 0, 0)
                : filas.get(0);
    }

    // ── Resumen semanal de incidencias para el gráfico de torta ──
    // Guava Cache: devuelve datos cacheados si fueron consultados hace menos de 5 min
    public AdminDTO.ResumenIncidenciasSemana obtenerResumenIncidenciasSemana() {
        try {
            return cacheIncidenciasSemana.get("actual");
        } catch (Exception e) {
            log.warn("Error al obtener cache de incidencias, consultando BD directamente", e);
            return cargarIncidenciasSemana();
        }
    }

    // ── Resumen semanal de tickets para el gráfico de dona ──
    // Guava Cache: evita consultas repetidas cuando varios admins abren el dashboard
    public AdminDTO.ResumenTicketsSemana obtenerResumenTicketsSemana() {
        try {
            return cacheTicketsSemana.get("actual");
        } catch (Exception e) {
            log.warn("Error al obtener cache de tickets, consultando BD directamente", e);
            return cargarTicketsSemana();
        }
    }

    // ── Carga real desde BD (llamada por el CacheLoader de Guava) ──
    private AdminDTO.ResumenIncidenciasSemana cargarIncidenciasSemana() {
        List<AdminDTO.ResumenIncidenciasSemana> filas = jdbc.query(
                "CALL sp_admin_incidencias_resumen_semana()",
                (rs, n) -> new AdminDTO.ResumenIncidenciasSemana(
                        rs.getInt("reportadas"),
                        rs.getInt("en_revision"),
                        rs.getInt("resueltas"),
                        rs.getInt("total")
                )
        );
        return filas.isEmpty()
                ? new AdminDTO.ResumenIncidenciasSemana(0, 0, 0, 0)
                : filas.get(0);
    }

    private AdminDTO.ResumenTicketsSemana cargarTicketsSemana() {
        List<AdminDTO.ResumenTicketsSemana> filas = jdbc.query(
                "CALL sp_admin_tickets_resumen_semana()",
                (rs, n) -> new AdminDTO.ResumenTicketsSemana(
                        rs.getInt("pendientes"),
                        rs.getInt("atendidos"),
                        rs.getInt("en_progreso"),
                        rs.getInt("evaluando"),
                        rs.getInt("total")
                )
        );
        return filas.isEmpty()
                ? new AdminDTO.ResumenTicketsSemana(0, 0, 0, 0, 0)
                : filas.get(0);
    }

    // ═══════════════════════════════════════════════════
    //  GESTIÓN DE INCIDENCIAS (admin)
    // ═══════════════════════════════════════════════════

    // ── Listar incidencias filtradas por tab (pendientes/revision/atendidas) ──
    public List<AdminDTO.IncidenciaAdminItem> listarIncidencias(String tab) {
        // Mapear tab del frontend al estado de la BD
        String filtroEstado = switch (StringUtils.lowerCase(StringUtils.trimToEmpty(tab))) {
            case "revision"  -> "EN_REVISION";
            case "atendidas" -> "RESUELTA";
            default          -> "REPORTADA";
        };

        return jdbc.query(
                """
                SELECT i.id_incidencia, i.tipo, i.asunto, i.estado, i.creado_en,
                       COALESCE(d.nombre_completo, u.codigo) AS solicitante
                FROM incidencias i
                JOIN usuarios_login u ON u.id_usuario = i.id_usuario
                LEFT JOIN usuario_detalle d ON d.id_usuario = u.id_usuario
                WHERE i.estado = ?
                ORDER BY i.creado_en DESC
                """,
                (rs, n) -> {
                    String tipo   = rs.getString("tipo");
                    String estado = rs.getString("estado");
                    boolean resaltado = "REPORTADA".equals(estado)
                            && "ACTUALIZACION".equalsIgnoreCase(tipo);
                    return new AdminDTO.IncidenciaAdminItem(
                            rs.getLong("id_incidencia"),
                            StringUtils.capitalize(StringUtils.lowerCase(tipo)),
                            "Topic: " + rs.getString("asunto"),
                            StringUtils.capitalize(StringUtils.lowerCase(estado)),
                            resaltado,
                            rs.getString("solicitante"),
                            timestampToString(rs.getTimestamp("creado_en"))
                    );
                },
                filtroEstado
        );
    }

    // ── Detalle de una incidencia para el modal del admin ──
    public AdminDTO.IncidenciaAdminDetalle obtenerDetalleIncidencia(Long id) {
        try {
            return jdbc.queryForObject(
                    """
                    SELECT i.id_incidencia, i.tipo, i.estado, i.contenido,
                           i.numero_ticket, i.creado_en,
                           COALESCE(ds.nombre_completo, us.codigo) AS solicitante,
                           COALESCE(da.nombre_completo, '') AS asignada_a
                    FROM incidencias i
                    JOIN usuarios_login us ON us.id_usuario = i.id_usuario
                    LEFT JOIN usuario_detalle ds ON ds.id_usuario = us.id_usuario
                    LEFT JOIN usuario_detalle da ON da.id_usuario = i.id_asignado
                    WHERE i.id_incidencia = ?
                    """,
                    (rs, n) -> new AdminDTO.IncidenciaAdminDetalle(
                            rs.getLong("id_incidencia"),
                            StringUtils.capitalize(StringUtils.lowerCase(rs.getString("tipo"))),
                            StringUtils.capitalize(StringUtils.lowerCase(rs.getString("estado"))),
                            rs.getString("solicitante"),
                            rs.getString("asignada_a"),
                            timestampToString(rs.getTimestamp("creado_en")),
                            rs.getString("contenido"),
                            rs.getInt("numero_ticket")
                    ),
                    id
            );
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Incidencia no encontrada");
        }
    }

    // ═══════════════════════════════════════════════════
    //  ACCIONES: EDITAR / ELIMINAR / ADJUNTOS
    // ═══════════════════════════════════════════════════

    // Carpeta donde se guardan los adjuntos de tickets
    @Value("${app.upload.adjuntos:uploads/adjuntos}")
    private String adjuntosDir;

    // Lista blanca de adjuntos permitidos. Bloquea HTML, SVG, JS y ejecutables que
    // podrian usarse para XSS almacenado o distribucion de malware al servirse el archivo.
    private static final Set<String> ADJUNTO_EXT_PERMITIDAS = Set.of(
            ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".webp",
            ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
            ".txt", ".csv", ".zip");
    private static final Set<String> ADJUNTO_MIME_PERMITIDOS = Set.of(
            "application/pdf", "image/png", "image/jpeg", "image/gif", "image/webp",
            "application/msword",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.ms-excel",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.ms-powerpoint",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "text/plain", "text/csv", "application/zip");

    // ── Editar ticket ──
    public AdminDTO.OperacionResponse editarTicket(int numero, AccionesAdminDTO.EditarTicketRequest req) {
        jdbc.update("CALL sp_admin_ticket_actualizar(?, ?, ?, ?, ?)",
                numero, req.getAsunto(), req.getTipo(), req.getPrioridad(), req.getDescripcion());
        return new AdminDTO.OperacionResponse("Ticket actualizado correctamente");
    }

    // ── Eliminar ticket ──
    public AdminDTO.OperacionResponse eliminarTicket(int numero) {
        // Borrar archivos físicos de los adjuntos antes de eliminar el ticket
        List<String> rutas = jdbc.query(
                "SELECT ta.ruta FROM ticket_adjuntos ta " +
                "JOIN tickets t ON t.id_ticket = ta.id_ticket WHERE t.numero_ticket = ?",
                (rs, n) -> rs.getString("ruta"), numero);
        rutas.forEach(this::borrarArchivoFisico);

        int filas = jdbc.update("CALL sp_admin_ticket_eliminar(?)", numero);
        if (filas == 0) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Ticket no encontrado");
        return new AdminDTO.OperacionResponse("Ticket eliminado correctamente");
    }

    // ── Editar incidencia ──
    public AdminDTO.OperacionResponse editarIncidencia(long id, AccionesAdminDTO.EditarIncidenciaRequest req) {
        jdbc.update("CALL sp_admin_incidencia_actualizar(?, ?, ?, ?)",
                id, req.getAsunto(), req.getTipo(), req.getContenido());
        return new AdminDTO.OperacionResponse("Incidencia actualizada correctamente");
    }

    // ── Eliminar incidencia ──
    public AdminDTO.OperacionResponse eliminarIncidencia(long id) {
        int filas = jdbc.update("CALL sp_admin_incidencia_eliminar(?)", id);
        if (filas == 0) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Incidencia no encontrada");
        return new AdminDTO.OperacionResponse("Incidencia eliminada correctamente");
    }

    // ── Subir un adjunto a un ticket ──
    public AccionesAdminDTO.AdjuntoResponse subirAdjunto(int numero, MultipartFile archivo) {
        if (archivo == null || archivo.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "No se envió ningún archivo");
        }
        if (archivo.getSize() > 5 * 1024 * 1024) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "El archivo no puede superar 5 MB");
        }

        // Validar tipo de archivo (lista blanca de extension + MIME) para evitar
        // subir HTML/SVG/JS que, al servirse en el mismo origen, habilitarian XSS almacenado.
        String nombreOriginal = archivo.getOriginalFilename() != null
                ? archivo.getOriginalFilename() : "archivo";
        int puntoExt = nombreOriginal.lastIndexOf('.');
        String extension = (puntoExt >= 0) ? nombreOriginal.substring(puntoExt).toLowerCase() : "";
        String mime = archivo.getContentType();
        if (!ADJUNTO_EXT_PERMITIDAS.contains(extension)
                || mime == null
                || !ADJUNTO_MIME_PERMITIDOS.contains(mime.toLowerCase())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Tipo de archivo no permitido. Formatos aceptados: PDF, imagenes, Office, TXT/CSV, ZIP.");
        }

        // Resolver el id_ticket interno a partir del numero
        Long idTicket;
        try {
            idTicket = jdbc.queryForObject(
                    "SELECT id_ticket FROM tickets WHERE numero_ticket = ?", Long.class, numero);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Ticket no encontrado");
        }

        // Guardar el archivo en disco con nombre único
        Path carpeta = Paths.get(adjuntosDir).toAbsolutePath();
        try {
            Files.createDirectories(carpeta);
        } catch (IOException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "No se pudo crear el directorio de adjuntos");
        }

        String original = nombreOriginal;
        String nombreFisico = "ticket_" + numero + "_" + UUID.randomUUID() + "_" + original.replaceAll("[^a-zA-Z0-9._-]", "_");
        Path destino = carpeta.resolve(nombreFisico);
        try {
            Files.copy(archivo.getInputStream(), destino, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error al guardar el archivo");
        }

        String rutaPublica = "/uploads/adjuntos/" + nombreFisico;
        int tamanoKb = (int) Math.max(1, archivo.getSize() / 1024);

        // Insertar la fila del adjunto
        jdbc.update(
                "INSERT INTO ticket_adjuntos (id_ticket, nombre_archivo, tamano_kb, ruta) VALUES (?, ?, ?, ?)",
                idTicket, original, tamanoKb, rutaPublica);

        Long idAdjunto = jdbc.queryForObject("SELECT LAST_INSERT_ID()", Long.class);

        return new AccionesAdminDTO.AdjuntoResponse(
                idAdjunto != null ? idAdjunto : 0, original, tamanoKb, rutaPublica, "Archivo agregado correctamente");
    }

    // ── Eliminar un adjunto específico de un ticket ──
    public AdminDTO.OperacionResponse eliminarAdjunto(int numero, long idAdjunto) {
        String ruta = jdbc.query(
                "SELECT ta.ruta FROM ticket_adjuntos ta JOIN tickets t ON t.id_ticket = ta.id_ticket " +
                "WHERE t.numero_ticket = ? AND ta.id_adjunto = ?",
                (rs, n) -> rs.getString("ruta"), numero, idAdjunto).stream().findFirst().orElse(null);

        int filas = jdbc.update("DELETE FROM ticket_adjuntos WHERE id_adjunto = ?", idAdjunto);
        if (filas == 0) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Adjunto no encontrado");
        borrarArchivoFisico(ruta);
        return new AdminDTO.OperacionResponse("Archivo eliminado correctamente");
    }

    // ── Eliminar TODOS los adjuntos de un ticket ──
    public AdminDTO.OperacionResponse eliminarTodosAdjuntos(int numero) {
        List<String> rutas = jdbc.query(
                "SELECT ta.ruta FROM ticket_adjuntos ta JOIN tickets t ON t.id_ticket = ta.id_ticket " +
                "WHERE t.numero_ticket = ?",
                (rs, n) -> rs.getString("ruta"), numero);

        jdbc.update(
                "DELETE ta FROM ticket_adjuntos ta JOIN tickets t ON t.id_ticket = ta.id_ticket " +
                "WHERE t.numero_ticket = ?", numero);
        rutas.forEach(this::borrarArchivoFisico);
        return new AdminDTO.OperacionResponse("Documentos eliminados correctamente");
    }

    // Borra un archivo del disco a partir de su ruta pública (/uploads/adjuntos/xxx)
    private void borrarArchivoFisico(String rutaPublica) {
        if (rutaPublica == null || rutaPublica.isBlank()) return;
        try {
            String nombre = Paths.get(rutaPublica).getFileName().toString();
            Files.deleteIfExists(Paths.get(adjuntosDir).toAbsolutePath().resolve(nombre));
        } catch (IOException ignored) {
            // No es crítico si no se puede borrar el archivo físico
        }
    }

    // ═══════════════════════════════════════════════════
    //  REPORTES
    // ═══════════════════════════════════════════════════

    // Arma la respuesta completa de la pantalla de Reportes:
    // KPIs (totales de toda la BD) + historial de tickets cerrados.
    public ReportesDTO.ReporteResponse obtenerReportes() {
        ReportesDTO.Kpis kpis = jdbc.queryForObject(
                "CALL sp_admin_reportes_kpis()",
                (rs, n) -> {
                    Integer promMin = rs.getObject("prom_minutos", Integer.class);
                    String tiempo = (promMin != null) ? promMin + " min" : "—";
                    return new ReportesDTO.Kpis(
                            rs.getInt("total_resueltos"),
                            rs.getInt("total_pendientes"),
                            rs.getInt("total_incidencias"),
                            tiempo
                    );
                }
        );

        List<ReportesDTO.HistorialItem> historial = jdbc.query(
                "CALL sp_admin_reportes_historial()",
                (rs, n) -> {
                    String estadoBd = rs.getString("estado");
                    boolean atendido = "ATENDIDO".equalsIgnoreCase(estadoBd);
                    Integer min = rs.getObject("minutos", Integer.class);

                    return new ReportesDTO.HistorialItem(
                            "#" + rs.getInt("numero_ticket"),
                            rs.getString("usuario"),
                            rs.getString("tipo_ticket"),
                            atendido ? "Resuelto" : "Cancelado",
                            atendido ? "badge-verde" : "badge-rojo",
                            formatearFechaCorta(rs.getTimestamp("fecha")),
                            (atendido && min != null) ? min + " min" : "—"
                    );
                }
        );

        return new ReportesDTO.ReporteResponse(kpis, historial);
    }

    // "2026-05-25 ..." → "25/05/2026"
    private String formatearFechaCorta(Timestamp ts) {
        if (ts == null) return "—";
        return ts.toLocalDateTime()
                 .format(java.time.format.DateTimeFormatter.ofPattern("dd/MM/yyyy"));
    }

    // ═══════════════════════════════════════════════════
    //  HELPERS PRIVADOS
    // ═══════════════════════════════════════════════════

    // Convierte un java.sql.Timestamp a String ISO o devuelve "" si es null
    private String timestampToString(Timestamp ts) {
        return ts != null ? ts.toLocalDateTime().toString() : "";
    }

    // Convierte un java.sql.Time a String "H:MM:SS" o devuelve "0:00" si es null
    private String formatearTime(Time t) {
        return t != null ? t.toString() : "0:00";
    }
}

package com.backdea365.app.service;

import com.backdea365.app.dto.UsuarioDTO;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.List;
import java.util.Set;

// Lógica de negocio para gestión de usuarios
// Usa consultas directas + sp_crear_usuario para la creación
// Librerías: Google Guava (Preconditions, ImmutableList), Apache Commons (StringUtils)
@Service
@RequiredArgsConstructor
public class ServicioUsuario {

    private final JdbcTemplate    jdbc;
    private final PasswordEncoder encoder;

    // Roles válidos del sistema (Guava ImmutableSet para constantes seguras)
    private static final Set<String> ROLES_VALIDOS =
            com.google.common.collect.ImmutableSet.of("EMPLEADO", "ADMINISTRADOR", "GERENTE");

    // ── Crear un nuevo usuario con código autoincremental ──
    // Verifica correo y DNI duplicados antes de insertar
    // El código se genera automáticamente según el rol (EMP###, ADM###, GER###)
    @Transactional
    public UsuarioDTO.CrearResponse crearUsuario(UsuarioDTO.CrearRequest req) {

        // Guava Preconditions: validación clara y expresiva de parámetros
        Preconditions.checkArgument(
                StringUtils.isNotBlank(req.getCorreo()),
                "El correo no puede estar vacío"
        );
        Preconditions.checkArgument(
                StringUtils.isNotBlank(req.getDni()),
                "El DNI no puede estar vacío"
        );
        Preconditions.checkArgument(
                StringUtils.isNotBlank(req.getNombreCompleto()),
                "El nombre no puede estar vacío"
        );

        String rol = StringUtils.upperCase(StringUtils.trimToEmpty(req.getRol()));
        Preconditions.checkArgument(
                ROLES_VALIDOS.contains(rol),
                "Rol inválido: %s. Valores permitidos: %s", rol, ROLES_VALIDOS
        );

        // Apache Commons: trimToLowerCase para limpiar el correo
        String correoLimpio = StringUtils.lowerCase(StringUtils.trimToEmpty(req.getCorreo()));

        // Verificar correo duplicado
        Integer existeCorreo = jdbc.queryForObject(
                "SELECT COUNT(*) FROM usuarios_login WHERE correo = ?",
                Integer.class, correoLimpio
        );
        if (existeCorreo != null && existeCorreo > 0) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "El correo ya está registrado");
        }

        // Apache Commons: trimToEmpty para limpiar el DNI
        String dniLimpio = StringUtils.trimToEmpty(req.getDni());

        // Verificar DNI duplicado
        Integer existeDni = jdbc.queryForObject(
                "SELECT COUNT(*) FROM usuario_detalle WHERE dni = ?",
                Integer.class, dniLimpio
        );
        if (existeDni != null && existeDni > 0) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "El DNI ya está registrado");
        }

        String codigo = generarCodigo(rol);

        // Apache Commons: construir nombre completo con join limpio
        String nombreCompleto = StringUtils.joinWith(" ",
                StringUtils.trimToEmpty(req.getNombreCompleto()),
                StringUtils.trimToEmpty(req.getApellidoCompleto())
        );

        String claveHash = encoder.encode(req.getContrasena());

        // Insertar en usuarios_login y capturar el ID generado con KeyHolder
        KeyHolder keyHolder = new GeneratedKeyHolder();
        jdbc.update(connection -> {
            PreparedStatement ps = connection.prepareStatement(
                    "INSERT INTO usuarios_login (codigo, correo, clave_hash, rol, activo) VALUES (?, ?, ?, ?, 1)",
                    Statement.RETURN_GENERATED_KEYS
            );
            ps.setString(1, codigo);
            ps.setString(2, correoLimpio);
            ps.setString(3, claveHash);
            ps.setString(4, rol);
            return ps;
        }, keyHolder);

        // Guava Preconditions: validar que el ID se generó correctamente
        Number idGenerado = keyHolder.getKey();
        Preconditions.checkNotNull(idGenerado, "Error al obtener ID del usuario generado");
        int idUsuario = idGenerado.intValue();

        // Insertar detalle del usuario en usuario_detalle
        jdbc.update(
                "INSERT INTO usuario_detalle (id_usuario, nombre_completo, pais, telefono, plataforma, dni) " +
                "VALUES (?, ?, 'Perú', ?, 'WEB', ?)",
                idUsuario, nombreCompleto,
                StringUtils.trimToEmpty(req.getTelefono()),
                dniLimpio
        );

        return new UsuarioDTO.CrearResponse(idUsuario, codigo, nombreCompleto, rol);
    }

    // ── Lista usuarios para el panel del admin ──
    // Retorna ImmutableList (Guava) para garantizar que la lista no se modifique
    private List<UsuarioDTO.PanelItem> listarPorEstado(boolean activo) {
        List<UsuarioDTO.PanelItem> resultado = jdbc.query(
                """
                SELECT u.id_usuario, d.nombre_completo, d.dni,
                       u.rol, u.codigo, u.correo
                FROM usuarios_login u
                LEFT JOIN usuario_detalle d ON d.id_usuario = u.id_usuario
                WHERE u.activo = ?
                ORDER BY u.id_usuario DESC
                """,
                (rs, n) -> new UsuarioDTO.PanelItem(
                        rs.getInt("id_usuario"),
                        rs.getString("nombre_completo"),
                        rs.getString("dni"),
                        formatearCargo(rs.getString("rol")),
                        rs.getString("codigo"),
                        rs.getString("correo"),
                        rs.getString("rol")
                ),
                activo ? 1 : 0
        );
        // Guava ImmutableList: la lista retornada no puede ser modificada
        return ImmutableList.copyOf(resultado);
    }

    // ── Lista todos los usuarios ACTIVOS para el panel del admin ──
    public List<UsuarioDTO.PanelItem> listarActivos() {
        return listarPorEstado(true);
    }

    // ── Lista todos los usuarios INACTIVOS (historial de eliminados) ──
    public List<UsuarioDTO.PanelItem> listarEliminados() {
        return listarPorEstado(false);
    }

    // ── Genera el código del usuario según el rol y el máximo existente ──
    // EMP001, EMP002... / ADM001... / GER001...
    // Usa MAX en vez de COUNT para evitar colisiones si se eliminan usuarios
    private String generarCodigo(String rol) {
        String prefijo = switch (rol) {
            case "ADMINISTRADOR" -> "ADM";
            case "GERENTE"       -> "GER";
            default              -> "EMP";
        };
        Integer maxNum = jdbc.queryForObject(
                "SELECT MAX(CAST(SUBSTRING(codigo, 4) AS UNSIGNED)) FROM usuarios_login WHERE codigo LIKE ?",
                Integer.class, prefijo + "%"
        );
        int siguiente = (maxNum == null ? 0 : maxNum) + 1;
        return String.format("%s%03d", prefijo, siguiente);
    }

    // Apache Commons: capitalize para formatear cargo legible
    private String formatearCargo(String rol) {
        if (StringUtils.isBlank(rol)) return "";
        return switch (rol.toUpperCase()) {
            case "ADMINISTRADOR" -> "Administrador";
            case "GERENTE"       -> "Gerente general";
            default              -> StringUtils.capitalize(rol.toLowerCase());
        };
    }
}

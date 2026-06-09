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

@Service
@RequiredArgsConstructor
public class ServicioUsuario {

    private final JdbcTemplate    jdbc;
    private final PasswordEncoder encoder;

    private static final Set<String> ROLES_VALIDOS =
            com.google.common.collect.ImmutableSet.of("EMPLEADO", "ADMINISTRADOR", "GERENTE");

    @Transactional
    public UsuarioDTO.CrearResponse crearUsuario(UsuarioDTO.CrearRequest req) {

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

        // ── CAMBIO: lanza ResponseStatusException en lugar de IllegalArgumentException ──
        if (!ROLES_VALIDOS.contains(rol)) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Rol inválido: " + rol + ". Valores permitidos: " + ROLES_VALIDOS
            );
        }

        String correoLimpio = StringUtils.lowerCase(StringUtils.trimToEmpty(req.getCorreo()));

        Integer existeCorreo = jdbc.queryForObject(
                "SELECT COUNT(*) FROM usuarios_login WHERE correo = ?",
                Integer.class, correoLimpio
        );
        if (existeCorreo != null && existeCorreo > 0) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "El correo ya está registrado");
        }

        String dniLimpio = StringUtils.trimToEmpty(req.getDni());

        Integer existeDni = jdbc.queryForObject(
                "SELECT COUNT(*) FROM usuario_detalle WHERE dni = ?",
                Integer.class, dniLimpio
        );
        if (existeDni != null && existeDni > 0) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "El DNI ya está registrado");
        }

        String codigo = generarCodigo(rol);

        String nombreCompleto = StringUtils.joinWith(" ",
                StringUtils.trimToEmpty(req.getNombreCompleto()),
                StringUtils.trimToEmpty(req.getApellidoCompleto())
        );

        String claveHash = encoder.encode(req.getContrasena());

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

        Number idGenerado = keyHolder.getKey();
        Preconditions.checkNotNull(idGenerado, "Error al obtener ID del usuario generado");
        int idUsuario = idGenerado.intValue();

        jdbc.update(
                "INSERT INTO usuario_detalle (id_usuario, nombre_completo, pais, telefono, plataforma, dni) " +
                        "VALUES (?, ?, 'Perú', ?, 'WEB', ?)",
                idUsuario, nombreCompleto,
                StringUtils.trimToEmpty(req.getTelefono()),
                dniLimpio
        );

        return new UsuarioDTO.CrearResponse(idUsuario, codigo, nombreCompleto, rol);
    }

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
        return ImmutableList.copyOf(resultado);
    }

    public List<UsuarioDTO.PanelItem> listarActivos() {
        return listarPorEstado(true);
    }

    public List<UsuarioDTO.PanelItem> listarEliminados() {
        return listarPorEstado(false);
    }

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

    private String formatearCargo(String rol) {
        if (StringUtils.isBlank(rol)) return "";
        return switch (rol.toUpperCase()) {
            case "ADMINISTRADOR" -> "Administrador";
            case "GERENTE"       -> "Gerente general";
            default              -> StringUtils.capitalize(rol.toLowerCase());
        };
    }
}
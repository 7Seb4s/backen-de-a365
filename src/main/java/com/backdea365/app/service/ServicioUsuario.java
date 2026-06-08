package com.backdena365.app.service;

import com.backdena365.app.dto.UsuarioDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.List;

// Lógica de negocio para gestión de usuarios
// Usa consultas directas + sp_crear_usuario para la creación
@Service
@RequiredArgsConstructor
public class ServicioUsuario {

    private final JdbcTemplate    jdbc;
    private final PasswordEncoder encoder;

    // ── Crear un nuevo usuario con código autoincremental ──
    // Verifica correo y DNI duplicados antes de insertar
    // El código se genera automáticamente según el rol (EMP###, ADM###, GER###)
    public UsuarioDTO.CrearResponse crearUsuario(UsuarioDTO.CrearRequest req) {

        String rol = req.getRol().toUpperCase();
        if (!rol.equals("EMPLEADO") && !rol.equals("ADMINISTRADOR") && !rol.equals("GERENTE")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Rol inválido");
        }

        // Verificar correo duplicado
        Integer existeCorreo = jdbc.queryForObject(
                "SELECT COUNT(*) FROM usuarios_login WHERE correo = ?",
                Integer.class, req.getCorreo().toLowerCase().trim()
        );
        if (existeCorreo != null && existeCorreo > 0) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "El correo ya está registrado");
        }

        // Verificar DNI duplicado
        Integer existeDni = jdbc.queryForObject(
                "SELECT COUNT(*) FROM usuario_detalle WHERE dni = ?",
                Integer.class, req.getDni().trim()
        );
        if (existeDni != null && existeDni > 0) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "El DNI ya está registrado");
        }

        String codigo        = generarCodigo(rol);
        String nombreCompleto = req.getNombreCompleto().trim() + " " + req.getApellidoCompleto().trim();
        String claveHash     = encoder.encode(req.getContrasena());

        // Insertar en usuarios_login y capturar el ID generado con KeyHolder
        KeyHolder keyHolder = new GeneratedKeyHolder();
        jdbc.update(connection -> {
            PreparedStatement ps = connection.prepareStatement(
                    "INSERT INTO usuarios_login (codigo, correo, clave_hash, rol, activo) VALUES (?, ?, ?, ?, 1)",
                    Statement.RETURN_GENERATED_KEYS
            );
            ps.setString(1, codigo);
            ps.setString(2, req.getCorreo().toLowerCase().trim());
            ps.setString(3, claveHash);
            ps.setString(4, rol);
            return ps;
        }, keyHolder);

        Number idGenerado = keyHolder.getKey();
        if (idGenerado == null) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Error al obtener ID del usuario");
        }
        int idUsuario = idGenerado.intValue();

        // Insertar detalle del usuario en usuario_detalle
        jdbc.update(
                "INSERT INTO usuario_detalle (id_usuario, nombre_completo, pais, telefono, plataforma, dni) " +
                "VALUES (?, ?, 'Perú', ?, 'WEB', ?)",
                idUsuario, nombreCompleto, req.getTelefono().trim(), req.getDni().trim()
        );

        return new UsuarioDTO.CrearResponse(idUsuario, codigo, nombreCompleto, rol);
    }

    // ── Lista todos los usuarios ACTIVOS para el panel del admin ──
    // Consulta directa que devuelve nombre, DNI y cargo de cada usuario activo
    public List<UsuarioDTO.PanelItem> listarActivos() {
        return jdbc.query(
                """
                SELECT u.id_usuario, d.nombre_completo, d.dni,
                       u.rol, u.codigo, u.correo
                FROM usuarios_login u
                LEFT JOIN usuario_detalle d ON d.id_usuario = u.id_usuario
                WHERE u.activo = 1
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
                )
        );
    }

    // ── Lista todos los usuarios INACTIVOS (historial de eliminados) ──
    // Misma consulta que listarActivos pero con activo = 0
    public List<UsuarioDTO.PanelItem> listarEliminados() {
        return jdbc.query(
                """
                SELECT u.id_usuario, d.nombre_completo, d.dni,
                       u.rol, u.codigo, u.correo
                FROM usuarios_login u
                LEFT JOIN usuario_detalle d ON d.id_usuario = u.id_usuario
                WHERE u.activo = 0
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
                )
        );
    }

    // ── Genera el código del usuario según el rol y el total existente ──
    // EMP001, EMP002... / ADM001... / GER001...
    private String generarCodigo(String rol) {
        String prefijo = switch (rol) {
            case "ADMINISTRADOR" -> "ADM";
            case "GERENTE"       -> "GER";
            default              -> "EMP";
        };
        Integer total = jdbc.queryForObject(
                "SELECT COUNT(*) FROM usuarios_login WHERE rol = ?",
                Integer.class, rol
        );
        int siguiente = (total == null ? 0 : total) + 1;
        return String.format("%s%03d", prefijo, siguiente);
    }

    // EMPLEADO → "Empleado", ADMINISTRADOR → "Administrador", GERENTE → "Gerente general"
    private String formatearCargo(String rol) {
        if (rol == null) return "";
        return switch (rol.toUpperCase()) {
            case "ADMINISTRADOR" -> "Administrador";
            case "GERENTE"       -> "Gerente general";
            default              -> "Empleado";
        };
    }
}

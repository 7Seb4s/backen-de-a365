package com.backdea365.app.service;

import com.backdea365.app.dto.PerfilDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

// Logica para ver y editar el perfil del usuario logueado
// Tambien maneja el cambio de contrasena estando autenticado
// Usa los stored procedures sp_perfil_obtener, sp_perfil_actualizar y sp_cambiar_clave
@Service
@RequiredArgsConstructor
public class ServicioPerfil {

    private final JdbcTemplate jdbc;
    private final PasswordEncoder encoder;

    // ── Obtener perfil del usuario logueado ──
    // Hacemos el SELECT directamente (mismo que el SP sp_perfil_obtener) para evitar
    // problemas con multiples result sets que devuelve MySQL al usar CALL
    public PerfilDTO.PerfilResponse obtenerPerfil(Integer idUsuario) {
        List<PerfilDTO.PerfilResponse> filas = jdbc.query(
                """
                SELECT
                    u.codigo            AS codigo_trabajador,
                    d.nombre_completo,
                    u.correo,
                    d.direccion,
                    d.telefono,
                    d.dni
                FROM usuarios_login u
                LEFT JOIN usuario_detalle d ON d.id_usuario = u.id_usuario
                WHERE u.id_usuario = ?
                  AND u.activo = 1
                LIMIT 1
                """,
                (rs, n) -> new PerfilDTO.PerfilResponse(
                        rs.getString("codigo_trabajador"),
                        rs.getString("nombre_completo"),
                        rs.getString("correo"),
                        rs.getString("direccion"),
                        rs.getString("telefono"),
                        rs.getString("dni")
                ),
                idUsuario
        );

        if (filas.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Usuario no encontrado");
        }
        return filas.get(0);
    }

    // ── Actualizar datos del perfil del usuario logueado ──
    // El SP sp_perfil_actualizar hace UPDATE en usuarios_login + INSERT/UPDATE en usuario_detalle
    public PerfilDTO.OperacionResponse actualizarPerfil(Integer idUsuario, PerfilDTO.ActualizarRequest req) {

        // Verificar que el correo no este usado por OTRO usuario
        Integer existeCorreo = jdbc.queryForObject(
                "SELECT COUNT(*) FROM usuarios_login WHERE correo = ? AND id_usuario <> ?",
                Integer.class, req.getCorreo().toLowerCase().trim(), idUsuario
        );
        if (existeCorreo != null && existeCorreo > 0) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "El correo ya esta registrado por otro usuario");
        }

        // Verificar que el DNI no este usado por OTRO usuario
        Integer existeDni = jdbc.queryForObject(
                "SELECT COUNT(*) FROM usuario_detalle WHERE dni = ? AND id_usuario <> ?",
                Integer.class, req.getDni().trim(), idUsuario
        );
        if (existeDni != null && existeDni > 0) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "El DNI ya esta registrado por otro usuario");
        }

        // Actualizar correo en usuarios_login
        jdbc.update(
                "UPDATE usuarios_login SET correo = ?, actualizado_en = NOW() WHERE id_usuario = ? AND activo = 1",
                req.getCorreo().toLowerCase().trim(), idUsuario
        );

        // UPSERT en usuario_detalle (insertar si no existe, actualizar si ya existe)
        jdbc.update(
                """
                INSERT INTO usuario_detalle
                    (id_usuario, nombre_completo, pais, telefono, locacion, plataforma, direccion, dni)
                VALUES (?, ?, 'Perú', ?, NULL, 'WEB', ?, ?)
                ON DUPLICATE KEY UPDATE
                    nombre_completo = VALUES(nombre_completo),
                    telefono        = VALUES(telefono),
                    direccion       = VALUES(direccion),
                    dni             = VALUES(dni)
                """,
                idUsuario,
                req.getNombreCompleto().trim(),
                req.getTelefono().trim(),
                req.getDireccion() == null ? null : req.getDireccion().trim(),
                req.getDni().trim()
        );

        return new PerfilDTO.OperacionResponse("Tu perfil ha sido actualizado correctamente.");
    }

    // ── Cambiar la contrasena del usuario logueado ──
    // Verifica la contrasena actual, valida que la nueva coincida con la confirmacion,
    // y actualiza el hash llamando a sp_cambiar_clave
    public PerfilDTO.OperacionResponse cambiarContrasena(Integer idUsuario, PerfilDTO.CambiarContrasenaRequest req) {

        // Validar que la nueva y la confirmacion coincidan
        if (!req.getNuevaContrasena().equals(req.getConfirmarContrasena())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Las contrasenas no coinciden");
        }

        // Obtener el hash actual de la BD
        String hashActual;
        try {
            hashActual = jdbc.queryForObject(
                    "SELECT clave_hash FROM usuarios_login WHERE id_usuario = ? AND activo = 1",
                    String.class, idUsuario
            );
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Usuario no encontrado");
        }

        // Verificar que la contrasena actual sea correcta
        if (hashActual == null || !encoder.matches(req.getContrasenaActual(), hashActual)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "La contrasena actual es incorrecta");
        }

        // Hashear la nueva contrasena con BCrypt y llamar al SP
        String nuevoHash = encoder.encode(req.getNuevaContrasena());
        jdbc.update("CALL sp_cambiar_clave(?, ?)", idUsuario, nuevoHash);

        return new PerfilDTO.OperacionResponse("Tu contrasena ha sido actualizada correctamente.");
    }
}
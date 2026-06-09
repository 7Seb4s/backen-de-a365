package com.backdea365.app.service;

import com.backdea365.app.dto.PerfilDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Set;
import java.util.UUID;

// Logica para ver y editar el perfil del usuario logueado
// Tambien maneja el cambio de contrasena estando autenticado
// y la subida de foto de perfil
@Service
@RequiredArgsConstructor
public class ServicioPerfil {

    private final JdbcTemplate jdbc;
    private final PasswordEncoder encoder;

    // Carpeta donde se guardan las fotos (configurada en application.properties)
    @Value("${app.upload.dir:uploads/fotos}")
    private String uploadDir;

    // Tipos de imagen permitidos
    private static final Set<String> TIPOS_PERMITIDOS = Set.of(
            "image/jpeg", "image/png", "image/webp", "image/gif"
    );

    // ── Obtener perfil del usuario logueado ──
    public PerfilDTO.PerfilResponse obtenerPerfil(Integer idUsuario) {
        List<PerfilDTO.PerfilResponse> filas = jdbc.query(
                """
                SELECT
                    u.codigo            AS codigo_trabajador,
                    d.nombre_completo,
                    u.correo,
                    d.direccion,
                    d.telefono,
                    d.dni,
                    d.foto_url
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
                        rs.getString("dni"),
                        rs.getString("foto_url")
                ),
                idUsuario
        );

        if (filas.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Usuario no encontrado");
        }
        return filas.get(0);
    }

    // ── Actualizar datos del perfil del usuario logueado ──
    public PerfilDTO.OperacionResponse actualizarPerfil(Integer idUsuario, PerfilDTO.ActualizarRequest req) {

        Integer existeCorreo = jdbc.queryForObject(
                "SELECT COUNT(*) FROM usuarios_login WHERE correo = ? AND id_usuario <> ?",
                Integer.class, req.getCorreo().toLowerCase().trim(), idUsuario
        );
        if (existeCorreo != null && existeCorreo > 0) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "El correo ya esta registrado por otro usuario");
        }

        Integer existeDni = jdbc.queryForObject(
                "SELECT COUNT(*) FROM usuario_detalle WHERE dni = ? AND id_usuario <> ?",
                Integer.class, req.getDni().trim(), idUsuario
        );
        if (existeDni != null && existeDni > 0) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "El DNI ya esta registrado por otro usuario");
        }

        jdbc.update(
                "UPDATE usuarios_login SET correo = ?, actualizado_en = NOW() WHERE id_usuario = ? AND activo = 1",
                req.getCorreo().toLowerCase().trim(), idUsuario
        );

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

    // ── Subir / reemplazar foto de perfil ──
    // Guarda el archivo en disco, borra la foto anterior si existia,
    // y persiste la URL publica en usuario_detalle.foto_url
    public PerfilDTO.FotoResponse subirFoto(Integer idUsuario, MultipartFile archivo) {

        // Validar que se envio un archivo
        if (archivo == null || archivo.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "No se envio ninguna imagen");
        }

        // Validar tipo MIME
        String contentType = archivo.getContentType();
        if (contentType == null || !TIPOS_PERMITIDOS.contains(contentType)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Tipo de archivo no permitido. Solo se aceptan: JPEG, PNG, WEBP, GIF");
        }

        // Validar tamaño (5 MB max, igual que multipart)
        if (archivo.getSize() > 5 * 1024 * 1024) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "La imagen no puede superar 5 MB");
        }

        // Crear la carpeta de destino si no existe
        Path carpeta = Paths.get(uploadDir).toAbsolutePath();
        try {
            Files.createDirectories(carpeta);
        } catch (IOException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "No se pudo crear el directorio de almacenamiento");
        }

        // Obtener la foto anterior para borrarla después
        String fotoAnterior = jdbc.queryForObject(
                "SELECT foto_url FROM usuario_detalle WHERE id_usuario = ?",
                String.class, idUsuario
        );

        // Generar nombre único para el archivo
        String extension = obtenerExtension(archivo.getOriginalFilename(), contentType);
        String nombreArchivo = "usuario_" + idUsuario + "_" + UUID.randomUUID() + extension;
        Path destino = carpeta.resolve(nombreArchivo);

        try {
            Files.copy(archivo.getInputStream(), destino, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Error al guardar la imagen: " + e.getMessage());
        }

        // URL pública que se expone al frontend (servida por Spring como recurso estático)
        String urlPublica = "/uploads/fotos/" + nombreArchivo;

        // Persistir en BD — usamos UPDATE simple porque el usuario siempre tiene
        // su fila en usuario_detalle (se crea al registrarse); el INSERT causaría
        // error por el NOT NULL de nombre_completo y otros campos obligatorios.
        jdbc.update(
                "UPDATE usuario_detalle SET foto_url = ? WHERE id_usuario = ?",
                urlPublica, idUsuario
        );

        // Borrar foto anterior del disco si existía
        if (fotoAnterior != null && !fotoAnterior.isBlank()) {
            String nombreViejo = Paths.get(fotoAnterior).getFileName().toString();
            Path archivoViejo = carpeta.resolve(nombreViejo);
            try {
                Files.deleteIfExists(archivoViejo);
            } catch (IOException ignored) {
                // No es crítico si no se puede borrar el archivo viejo
            }
        }

        return new PerfilDTO.FotoResponse("Foto de perfil actualizada correctamente.", urlPublica);
    }

    // ── Cambiar la contrasena del usuario logueado ──
    public PerfilDTO.OperacionResponse cambiarContrasena(Integer idUsuario, PerfilDTO.CambiarContrasenaRequest req) {

        if (!req.getNuevaContrasena().equals(req.getConfirmarContrasena())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Las contrasenas no coinciden");
        }

        String hashActual;
        try {
            hashActual = jdbc.queryForObject(
                    "SELECT clave_hash FROM usuarios_login WHERE id_usuario = ? AND activo = 1",
                    String.class, idUsuario
            );
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Usuario no encontrado");
        }

        if (hashActual == null || !encoder.matches(req.getContrasenaActual(), hashActual)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "La contrasena actual es incorrecta");
        }

        String nuevoHash = encoder.encode(req.getNuevaContrasena());
        jdbc.update("CALL sp_cambiar_clave(?, ?)", idUsuario, nuevoHash);

        return new PerfilDTO.OperacionResponse("Tu contrasena ha sido actualizada correctamente.");
    }

    // ── Helpers ──
    private String obtenerExtension(String nombreOriginal, String contentType) {
        if (nombreOriginal != null && nombreOriginal.contains(".")) {
            return nombreOriginal.substring(nombreOriginal.lastIndexOf(".")).toLowerCase();
        }
        return switch (contentType) {
            case "image/png"  -> ".png";
            case "image/webp" -> ".webp";
            case "image/gif"  -> ".gif";
            default           -> ".jpg";
        };
    }
}
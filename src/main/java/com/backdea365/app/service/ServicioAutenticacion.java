package com.backdea365.app.service;

import com.backdea365.app.dto.AuthDTO;
import com.backdea365.app.model.UsuarioLogin;
import com.backdea365.app.repository.RepositorioUsuario;
import com.backdea365.app.security.UtilJWT;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

// Logica de negocio del login normal (codigo + contrasena)
@Service
@RequiredArgsConstructor
public class ServicioAutenticacion {

    private final RepositorioUsuario repositorioUsuario;
    private final UtilJWT utilJWT;
    private final PasswordEncoder encoder;
    private final JdbcTemplate jdbc;

    // Verifica las credenciales del usuario y genera un token JWT si son correctas
    // Paso 1: busca el usuario por codigo, si no existe responde 404
    // Paso 2: compara la contrasena con BCrypt, si no coincide responde 401
    // Paso 3: genera el token JWT y devuelve los datos del usuario
    public AuthDTO.LoginResponse login(AuthDTO.LoginRequest peticion) {

        // Buscar el usuario activo por codigo
        UsuarioLogin usuario = repositorioUsuario
                .buscarPorCodigo(peticion.getCodigo())
                .orElseThrow(() ->
                    // El codigo ingresado no existe en la BD
                    new ResponseStatusException(HttpStatus.NOT_FOUND, "Codigo no encontrado")
                );

        // Verificar que la contrasena coincida con el hash BCrypt guardado
        if (!encoder.matches(peticion.getPassword(), usuario.getClaveHash())) {
            // El usuario existe pero la contrasena es incorrecta
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Contrasena incorrecta");
        }

        // Buscar el nombre completo en la tabla usuario_detalle
        String nombre = buscarNombreCompleto(usuario.getIdUsuario());

        // Generar el token JWT firmado
        String token = utilJWT.generarToken(usuario.getCodigo(), usuario.getRol().name());

        // Devolver la respuesta completa al frontend
        return new AuthDTO.LoginResponse(
                token,
                "Bearer",
                usuario.getIdUsuario(),
                usuario.getCodigo(),
                nombre != null ? nombre : usuario.getCodigo(),
                usuario.getRol().name()
        );
    }

    // Consulta usuario_detalle para obtener el nombre del trabajador
    // Retorna null si el usuario todavia no tiene perfil creado
    private String buscarNombreCompleto(Integer idUsuario) {
        try {
            return jdbc.queryForObject(
                "SELECT nombre_completo FROM usuario_detalle WHERE id_usuario = ?",
                String.class,
                idUsuario
            );
        } catch (Exception e) {
            return null;
        }
    }
}

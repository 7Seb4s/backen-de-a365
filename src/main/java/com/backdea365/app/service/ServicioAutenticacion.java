package com.backdea365.app.service;

// -------------------------------------------------------------
// ServicioAutenticacion.java
// Contiene la logica de negocio del login.
// Distingue entre "codigo no existe" (404) y "contrasena incorrecta" (401)
// para que el frontend pueda mostrar el mensaje correcto en cada campo.
// -------------------------------------------------------------

import com.backdea365.app.dto.AuthDTO;
import com.backdea365.app.model.UsuarioLogin;
import com.backdea365.app.repository.RepositorioUsuario;
import com.backdea365.app.security.UtilJWT;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
public class ServicioAutenticacion {

    private final RepositorioUsuario repositorioUsuario;
    private final UtilJWT utilJWT;
    private final PasswordEncoder encoder;
    private final JdbcTemplate jdbc;

    // -- LOGIN ---------------------------------------------------
    // 1. Busca el usuario por codigo. Si no existe responde 404.
    // 2. Verifica la contrasena con BCrypt. Si no coincide responde 401.
    // 3. Si todo es correcto genera el token JWT y retorna los datos.
    public AuthDTO.LoginResponse login(AuthDTO.LoginRequest peticion) {

        // Paso 1: buscar el usuario activo por codigo
        UsuarioLogin usuario = repositorioUsuario
                .buscarPorCodigo(peticion.getCodigo())
                .orElseThrow(() ->
                    // 404: el codigo ingresado no existe en la BD
                    new ResponseStatusException(HttpStatus.NOT_FOUND, "Codigo no encontrado")
                );

        // Paso 2: verificar que la contrasena coincida con el hash BCrypt
        if (!encoder.matches(peticion.getPassword(), usuario.getClaveHash())) {
            // 401: el usuario existe pero la contrasena es incorrecta
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Contrasena incorrecta");
        }

        // Paso 3: buscar el nombre completo en usuario_detalle
        String nombre = buscarNombreCompleto(usuario.getIdUsuario());

        // Paso 4: generar el token JWT firmado
        String token = utilJWT.generarToken(usuario.getCodigo(), usuario.getRol().name());

        // Paso 5: retornar la respuesta completa al frontend
        return new AuthDTO.LoginResponse(
                token,
                "Bearer",
                usuario.getIdUsuario(),
                usuario.getCodigo(),
                nombre != null ? nombre : usuario.getCodigo(),
                usuario.getRol().name()
        );
    }

    // -- BUSCAR NOMBRE COMPLETO (privado) ----------------------
    // Consulta la tabla usuario_detalle para obtener el nombre del trabajador.
    // Retorna null si el usuario todavia no tiene perfil creado.
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

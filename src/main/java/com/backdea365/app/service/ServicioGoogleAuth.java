package com.backdea365.app.service;

import com.backdea365.app.dto.AuthDTO;
import com.backdea365.app.model.UsuarioLogin;
import com.backdea365.app.repository.RepositorioUsuario;
import com.backdea365.app.security.UtilJWT;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Collections;

// Logica del login con Google Sign-In
// Valida el ID Token de Google y genera un JWT propio del sistema
@Service
@RequiredArgsConstructor
public class ServicioGoogleAuth {

    private final RepositorioUsuario repositorioUsuario;
    private final UtilJWT utilJWT;
    private final JdbcTemplate jdbc;

    // Client ID de la app en Google Cloud Console (application.properties)
    @Value("${google.client-id}")
    private String googleClientId;

    // Valida el credential de Google, verifica que el correo este registrado
    // y devuelve el mismo JWT que el login normal
    // Paso 1: verifica el token con los servidores de Google
    // Paso 2: extrae el correo del token verificado
    // Paso 3: busca el correo en la BD
    // Paso 4: genera el JWT propio y devuelve la respuesta
    public AuthDTO.LoginResponse loginConGoogle(String credential) {

        // Verificar el token con Google
        GoogleIdToken.Payload payload = verificarTokenGoogle(credential);

        // Extraer el correo del token
        String correo = payload.getEmail();

        // Buscar el correo en la BD
        UsuarioLogin usuario = repositorioUsuario
                .buscarPorCorreo(correo)
                .orElseThrow(() ->
                    // El correo de Google no esta registrado en el sistema
                    new ResponseStatusException(
                        HttpStatus.NOT_FOUND,
                        "El correo " + correo + " no esta registrado en el sistema"
                    )
                );

        // Verificar que el usuario este activo
        if (!usuario.getActivo()) {
            throw new ResponseStatusException(
                HttpStatus.FORBIDDEN,
                "Tu cuenta esta desactivada. Contacta al administrador."
            );
        }

        // Buscar el nombre completo en usuario_detalle
        String nombre = buscarNombreCompleto(usuario.getIdUsuario());

        // Generar JWT propio del sistema
        String token = utilJWT.generarToken(usuario.getCodigo(), usuario.getRol().name());

        // Devolver la misma respuesta que el login normal
        // Buscar foto de perfil
        String fotoUrl = null;
        try {
            fotoUrl = jdbc.queryForObject(
                    "SELECT foto_url FROM usuario_detalle WHERE id_usuario = ?",
                    String.class, usuario.getIdUsuario()
            );
        } catch (Exception ignored) {}

        return new AuthDTO.LoginResponse(
                token,
                "Bearer",
                usuario.getIdUsuario(),
                usuario.getCodigo(),
                nombre != null ? nombre : usuario.getCodigo(),
                usuario.getRol().name(),
                fotoUrl
        );
    }

    // Llama a los servidores de Google para confirmar que el token es autentico
    // Si el token es invalido o expirado responde 401
    private GoogleIdToken.Payload verificarTokenGoogle(String credential) {
        try {
            GoogleIdTokenVerifier verificador = new GoogleIdTokenVerifier.Builder(
                    new NetHttpTransport(),
                    GsonFactory.getDefaultInstance()
            )
            // Solo acepta tokens emitidos para nuestra app
            .setAudience(Collections.singletonList(googleClientId))
            .build();

            GoogleIdToken idToken = verificador.verify(credential);

            if (idToken == null) {
                throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Token de Google invalido o expirado"
                );
            }

            return idToken.getPayload();

        } catch (ResponseStatusException e) {
            throw e;
        } catch (Exception e) {
            throw new ResponseStatusException(
                HttpStatus.UNAUTHORIZED,
                "Error al verificar el token de Google: " + e.getMessage()
            );
        }
    }

    // Consulta usuario_detalle para obtener el nombre del trabajador
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

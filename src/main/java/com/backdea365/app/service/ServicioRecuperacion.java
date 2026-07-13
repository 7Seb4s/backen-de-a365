package com.backdea365.app.service;

import com.backdea365.app.dto.RecuperarDTO;
import com.backdea365.app.model.ResetPassword;
import com.backdea365.app.model.UsuarioLogin;
import com.backdea365.app.repository.RepositorioResetPassword;
import com.backdea365.app.repository.RepositorioUsuario;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.TimeUnit;

// Logica del flujo completo de recuperacion de contrasena
// Usa Resend API para enviar el codigo al correo del usuario
@Slf4j
@Service
@RequiredArgsConstructor
public class ServicioRecuperacion {

    private final RepositorioUsuario       repoUsuario;
    private final RepositorioResetPassword repoReset;
    private final PasswordEncoder          encoder;

    // API key de Resend (application.properties)
    @Value("${resend.api-key}")
    private String resendApiKey;

    // Correo desde el que se envian los emails (application.properties)
    @Value("${resend.from}")
    private String resendFrom;

    // Generador criptograficamente seguro para el codigo de recuperacion
    private final SecureRandom secureRandom = new SecureRandom();

    // Anti fuerza bruta del codigo: cuenta verificaciones fallidas por correo.
    // Al llegar a MAX_INTENTOS_CODIGO el codigo se invalida y hay que pedir uno nuevo.
    private static final int MAX_INTENTOS_CODIGO = 5;
    private final Cache<String, Integer> intentosCodigo = CacheBuilder.newBuilder()
            .expireAfterWrite(15, TimeUnit.MINUTES)
            .maximumSize(10_000)
            .build();

    // Paso 1: verifica que el correo exista, genera un codigo de 6 digitos,
    // lo guarda en BD con 15 minutos de expiracion y lo envia por email via Resend
    @Transactional
    public void solicitarCodigo(RecuperarDTO.SolicitarRequest req) {

        // Verificar que el correo existe en el sistema
        repoUsuario.buscarPorCorreo(req.getCorreo())
            .orElseThrow(() -> new ResponseStatusException(
                HttpStatus.NOT_FOUND,
                "No encontramos una cuenta con ese correo."
            ));

        // Invalidar codigos anteriores del mismo correo para evitar duplicados
        repoReset.invalidarCodigos(req.getCorreo());

        // Generar codigo de 6 digitos con generador seguro (000000 - 999999)
        String codigo = String.format("%06d", secureRandom.nextInt(1_000_000));

        // Guardar el codigo en la BD con 15 minutos de expiracion
        ResetPassword reset = new ResetPassword();
        reset.setCorreo(req.getCorreo());
        reset.setCodigo(codigo);
        reset.setExpiracion(LocalDateTime.now().plusMinutes(15));
        reset.setUsado(false);
        repoReset.save(reset);

        // Enviar el codigo al correo del usuario via Resend
        enviarCorreo(req.getCorreo(), codigo);

        log.info("Codigo de recuperacion enviado a: {}", req.getCorreo());
    }

    // Paso 2: verifica que el codigo recibido sea correcto y no haya expirado
    // Responde 400 si el codigo es incorrecto o ya expiro
    public void verificarCodigo(RecuperarDTO.VerificarRequest req) {
        verificarNoBloqueado(req.getCorreo());

        ResetPassword reset = repoReset
            .buscarCodigoVigente(req.getCorreo(), LocalDateTime.now())
            .orElseThrow(() -> new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "El codigo es incorrecto o ya expiro."
            ));

        if (!reset.getCodigo().equals(req.getCodigo())) {
            registrarIntentoFallidoCodigo(req.getCorreo());
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "El codigo es incorrecto o ya expiro."
            );
        }

        // Codigo correcto: limpiar el contador de intentos
        intentosCodigo.invalidate(req.getCorreo());
    }

    // Paso 3: verifica el codigo una vez mas, encripta la nueva contrasena con BCrypt,
    // la guarda en la BD y marca el codigo como usado para que no se pueda reutilizar
    @Transactional
    public void cambiarPassword(RecuperarDTO.CambiarRequest req) {

        verificarNoBloqueado(req.getCorreo());

        // Verificar el codigo una vez mas antes de cambiar la contrasena
        ResetPassword reset = repoReset
            .buscarCodigoVigente(req.getCorreo(), LocalDateTime.now())
            .orElseThrow(() -> new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "El codigo es incorrecto o ya expiro."
            ));

        if (!reset.getCodigo().equals(req.getCodigo())) {
            registrarIntentoFallidoCodigo(req.getCorreo());
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "El codigo es incorrecto o ya expiro."
            );
        }

        // Buscar el usuario y actualizar su contrasena encriptada
        UsuarioLogin usuario = repoUsuario.buscarPorCorreo(req.getCorreo())
            .orElseThrow(() -> new ResponseStatusException(
                HttpStatus.NOT_FOUND, "Usuario no encontrado."
            ));

        usuario.setClaveHash(encoder.encode(req.getNuevaPassword()));
        repoUsuario.save(usuario);

        // Marcar el codigo como usado para que no se pueda volver a usar
        reset.setUsado(true);
        repoReset.save(reset);

        log.info("Contrasena actualizada para: {}", req.getCorreo());
    }

    // Lanza 429 si el correo supero el maximo de intentos de verificacion del codigo
    private void verificarNoBloqueado(String correo) {
        Integer intentos = intentosCodigo.getIfPresent(correo);
        if (intentos != null && intentos >= MAX_INTENTOS_CODIGO) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,
                "Demasiados intentos. Solicita un nuevo codigo de recuperacion.");
        }
    }

    // Suma un intento fallido y, al llegar al maximo, invalida el codigo vigente
    private void registrarIntentoFallidoCodigo(String correo) {
        Integer actual = intentosCodigo.getIfPresent(correo);
        int nuevo = (actual == null) ? 1 : actual + 1;
        intentosCodigo.put(correo, nuevo);
        if (nuevo >= MAX_INTENTOS_CODIGO) {
            repoReset.invalidarCodigos(correo); // quema el codigo tras demasiados fallos
        }
    }

    // Llama a la API de Resend para enviar el codigo al correo del usuario
    // Si falla responde 500 con mensaje de error
    private void enviarCorreo(String destinatario, String codigo) {
        try {
            RestTemplate restTemplate = new RestTemplate();

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(resendApiKey);

            // HTML del correo con el codigo destacado
            String html = """
                <div style="font-family: Arial, sans-serif; max-width: 500px; margin: auto; padding: 30px; border: 1px solid #e0e0e0; border-radius: 8px;">
                    <h2 style="color: #1a2744;">Recupera tu contraseña</h2>
                    <p>Usa el siguiente codigo para restablecer tu contrasena. <strong>Expira en 15 minutos.</strong></p>
                    <div style="font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #1a2744; background: #f0f4ff; padding: 20px; text-align: center; border-radius: 6px; margin: 20px 0;">
                        %s
                    </div>
                    <p style="color: #666; font-size: 13px;">Si no solicitaste este codigo, ignora este mensaje.</p>
                    <p style="color: #999; font-size: 12px;">© 2026 Impulsa A365 — Group16</p>
                </div>
                """.formatted(codigo);

            Map<String, Object> body = Map.of(
                "from",    resendFrom,
                "to",      new String[]{ destinatario },
                "subject", "Codigo de recuperacion — Impulsa A365",
                "html",    html
            );

            HttpEntity<Map<String, Object>> request = new HttpEntity<>(body, headers);

            // Enviar el correo a la API de Resend
            restTemplate.postForEntity(
                "https://api.resend.com/emails",
                request,
                Map.class
            );

        } catch (Exception e) {
            log.error("Error al enviar correo de recuperacion: {}", e.getMessage());
            throw new ResponseStatusException(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Error al enviar el correo. Intenta de nuevo."
            );
        }
    }
}

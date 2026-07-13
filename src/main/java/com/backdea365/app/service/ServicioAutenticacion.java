package com.backdea365.app.service;

import com.backdea365.app.dto.AuthDTO;
import com.backdea365.app.model.UsuarioLogin;
import com.backdea365.app.repository.RepositorioUsuario;
import com.backdea365.app.security.UtilJWT;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.concurrent.TimeUnit;

// Logica de negocio del login normal (codigo + contrasena)
// Usa Guava Cache para evitar consultas repetidas a usuario_detalle
@Service
@RequiredArgsConstructor
public class ServicioAutenticacion {

    private final RepositorioUsuario repositorioUsuario;
    private final UtilJWT utilJWT;
    private final PasswordEncoder encoder;
    private final JdbcTemplate jdbc;

    // Cache de Guava: guarda el nombre completo por id_usuario
    // Expira a las 8 horas (igual que el JWT) y tiene un maximo de 500 entradas
    private Cache<Integer, String> cacheNombres;

    // ── Anti fuerza bruta: cuenta intentos de login fallidos por codigo ──
    // Tras MAX_INTENTOS fallos el codigo queda bloqueado durante la ventana de la cache
    private static final int MAX_INTENTOS = 5;
    private Cache<String, Integer> intentosFallidos;

    // Hash BCrypt ficticio para igualar el tiempo de respuesta cuando el codigo no existe
    // (evita distinguir "usuario inexistente" de "contrasena incorrecta" por timing)
    private static final String HASH_FICTICIO =
            "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

    @PostConstruct
    private void inicializarCache() {
        cacheNombres = CacheBuilder.newBuilder()
                .expireAfterWrite(8, TimeUnit.HOURS)  // se limpia al mismo tiempo que el JWT
                .maximumSize(500)                      // maximo 500 usuarios en cache
                .build();

        // Los intentos fallidos se olvidan tras 15 minutos (desbloqueo automatico)
        intentosFallidos = CacheBuilder.newBuilder()
                .expireAfterWrite(15, TimeUnit.MINUTES)
                .maximumSize(10_000)
                .build();
    }

    // Verifica las credenciales del usuario y genera un token JWT si son correctas
    // Paso 1: busca el usuario por codigo, si no existe responde 404
    // Paso 2: compara la contrasena con BCrypt, si no coincide responde 401
    // Paso 3: genera el token JWT y devuelve los datos del usuario
    public AuthDTO.LoginResponse login(AuthDTO.LoginRequest peticion) {

        String codigo = peticion.getCodigo();

        // Bloqueo temporal tras demasiados intentos fallidos (anti fuerza bruta)
        Integer fallosPrevios = intentosFallidos.getIfPresent(codigo);
        if (fallosPrevios != null && fallosPrevios >= MAX_INTENTOS) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,
                    "Demasiados intentos fallidos. Intenta de nuevo en unos minutos.");
        }

        // Buscar el usuario activo por codigo (sin revelar si existe o no)
        UsuarioLogin usuario = repositorioUsuario.buscarPorCodigo(codigo).orElse(null);

        // Verificar la contrasena. Si el usuario no existe se compara igual contra un
        // hash ficticio para que el tiempo de respuesta sea el mismo (evita enumeracion).
        boolean credencialesOk;
        if (usuario != null) {
            credencialesOk = encoder.matches(peticion.getPassword(), usuario.getClaveHash());
        } else {
            encoder.matches(peticion.getPassword(), HASH_FICTICIO); // iguala el tiempo
            credencialesOk = false;
        }

        if (!credencialesOk) {
            registrarIntentoFallido(codigo);
            // Mensaje y codigo genericos: no distingue "no existe" de "contrasena incorrecta"
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Credenciales invalidas");
        }

        // Login correcto: limpiar el contador de intentos
        intentosFallidos.invalidate(codigo);

        // Buscar el nombre completo usando el cache de Guava
        // Si ya esta en cache no hace la query a la BD
        String nombre = buscarNombreConCache(usuario.getIdUsuario());

        // Buscar la foto de perfil del usuario
        String fotoUrl = null;
        try {
            fotoUrl = jdbc.queryForObject(
                    "SELECT foto_url FROM usuario_detalle WHERE id_usuario = ?",
                    String.class, usuario.getIdUsuario()
            );
        } catch (Exception ignored) {}

        // Generar el token JWT firmado
        String token = utilJWT.generarToken(usuario.getCodigo(), usuario.getRol().name());

        // Devolver la respuesta completa al frontend
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

    // Busca el nombre en el cache primero; si no esta, consulta la BD y lo guarda
    private String buscarNombreConCache(Integer idUsuario) {
        // Intentar obtener desde el cache
        String nombreCacheado = cacheNombres.getIfPresent(idUsuario);
        if (nombreCacheado != null) {
            return nombreCacheado;
        }

        // No estaba en cache: consultar la BD
        String nombre = buscarNombreCompleto(idUsuario);

        // Guardar en cache para proximas consultas (si no es null)
        if (nombre != null) {
            cacheNombres.put(idUsuario, nombre);
        }

        return nombre;
    }

    // Suma un intento de login fallido para el codigo dado
    private void registrarIntentoFallido(String codigo) {
        Integer actual = intentosFallidos.getIfPresent(codigo);
        intentosFallidos.put(codigo, actual == null ? 1 : actual + 1);
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
package com.backdea365.app.security;

// ─────────────────────────────────────────────────────────────
// UtilJWT.java
// Genera y valida tokens JWT usando la librería JJWT.
// El token contiene el código del usuario, su rol y fecha de expiración.
// Se firma con la clave secreta definida en application.properties.
// ─────────────────────────────────────────────────────────────

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class UtilJWT {

    // Clave secreta leída desde application.properties (jwt.secret)
    @Value("${jwt.secret}")
    private String secreto;

    // Tiempo de vida del token en milisegundos (jwt.expiration = 86400000 = 24h)
    @Value("${jwt.expiration}")
    private long expiracion;

    // ── GENERAR TOKEN ─────────────────────────────────────────
    // Crea un JWT firmado con el código del usuario como "subject"
    // y el rol como claim adicional.
    public String generarToken(String codigo, String rol) {
        return Jwts.builder()
                .setSubject(codigo)                         // identidad del usuario
                .claim("rol", rol)                          // dato extra: rol
                .setIssuedAt(new Date())                    // fecha de creación
                .setExpiration(new Date(System.currentTimeMillis() + expiracion))
                .signWith(obtenerClave(), SignatureAlgorithm.HS512)
                .compact();
    }

    // ── EXTRAER CÓDIGO DEL TOKEN ──────────────────────────────
    // Lee el "subject" del JWT, que es el código del usuario.
    public String extraerCodigo(String token) {
        return parsearToken(token).getBody().getSubject();
    }

    // ── VALIDAR TOKEN ─────────────────────────────────────────
    // Verifica la firma y que el token no haya expirado.
    // Retorna true si es válido, false si no.
    public boolean esTokenValido(String token) {
        try {
            parsearToken(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            // Token inválido, expirado o malformado
            return false;
        }
    }

    // ── PARSEAR TOKEN (uso interno) ───────────────────────────
    // Decodifica el token y retorna sus claims (datos internos).
    private Jws<Claims> parsearToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(obtenerClave())
                .build()
                .parseClaimsJws(token);
    }

    // ── CONSTRUIR CLAVE DE FIRMA ──────────────────────────────
    // Convierte el string del secreto en una clave criptográfica.
    private Key obtenerClave() {
        return Keys.hmacShaKeyFor(secreto.getBytes());
    }
}

package com.backdea365.app.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

// Genera y valida tokens JWT usando la libreria JJWT
// El token contiene el codigo del usuario, su rol y fecha de expiracion
@Component
public class UtilJWT {

    // Clave secreta leida desde application.properties (jwt.secret)
    @Value("${jwt.secret}")
    private String secreto;

    // Tiempo de vida del token en milisegundos (jwt.expiration = 28800000 = 8 horas)
    @Value("${jwt.expiration}")
    private long expiracion;

    // Genera un JWT firmado con el codigo del usuario como subject y el rol como claim
    public String generarToken(String codigo, String rol) {
        return Jwts.builder()
                .setSubject(codigo)                         // identidad del usuario
                .claim("rol", rol)                          // dato extra: rol
                .setIssuedAt(new Date())                    // fecha de creacion
                .setExpiration(new Date(System.currentTimeMillis() + expiracion))
                .signWith(obtenerClave(), SignatureAlgorithm.HS512)
                .compact();
    }

    // Lee el codigo del usuario desde el subject del token
    public String extraerCodigo(String token) {
        return parsearToken(token).getBody().getSubject();
    }

    // Verifica la firma y que el token no haya expirado
    // Retorna true si es valido, false si no
    public boolean esTokenValido(String token) {
        try {
            parsearToken(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            // Token invalido, expirado o malformado
            return false;
        }
    }

    // Decodifica el token y retorna sus claims (uso interno)
    private Jws<Claims> parsearToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(obtenerClave())
                .build()
                .parseClaimsJws(token);
    }

    // Convierte el string del secreto en una clave criptografica para firmar
    private Key obtenerClave() {
        return Keys.hmacShaKeyFor(secreto.getBytes());
    }
}

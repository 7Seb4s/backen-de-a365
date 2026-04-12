package com.backdea365.app.model;

// ─────────────────────────────────────────────────────────────
// UsuarioLogin.java
// Entidad JPA que mapea la tabla 'usuarios_login' de la base de datos.
// Hibernate la usa para leer y escribir usuarios.
// ─────────────────────────────────────────────────────────────

import jakarta.persistence.*;
import lombok.Data;

@Data
@Entity
@Table(name = "usuarios_login")
public class UsuarioLogin {

    // Clave primaria autoincremental
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_usuario")
    private Integer idUsuario;

    // Código único del trabajador (ej: "EMP001")
    @Column(name = "codigo", nullable = false, unique = true)
    private String codigo;

    // Correo electrónico único
    @Column(name = "correo", nullable = false, unique = true)
    private String correo;

    // Contraseña encriptada con BCrypt
    @Column(name = "clave_hash", nullable = false)
    private String claveHash;

    // Rol del usuario: EMPLEADO, ADMINISTRADOR o GERENTE
    @Enumerated(EnumType.STRING)
    @Column(name = "rol", nullable = false)
    private Rol rol;

    // Si el usuario está activo (1) o desactivado (0)
    @Column(name = "activo", nullable = false)
    private Boolean activo;

    // Enum que coincide exactamente con los valores del ENUM de MySQL
    public enum Rol {
        EMPLEADO, ADMINISTRADOR, GERENTE
    }
}

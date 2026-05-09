package com.backdea365.app.model;

import jakarta.persistence.*;
import lombok.Data;

// Mapea la tabla usuarios_login de la base de datos
@Data
@Entity
@Table(name = "usuarios_login")
public class UsuarioLogin {

    // ID autoincremental de la tabla
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_usuario")
    private Integer idUsuario;

    // Codigo unico del trabajador (ej: EMP001)
    @Column(name = "codigo", nullable = false, unique = true)
    private String codigo;

    // Correo electronico unico del usuario
    @Column(name = "correo", nullable = false, unique = true)
    private String correo;

    // Contrasena encriptada con BCrypt
    @Column(name = "clave_hash", nullable = false)
    private String claveHash;

    // Rol del usuario: EMPLEADO, ADMINISTRADOR o GERENTE
    @Enumerated(EnumType.STRING)
    @Column(name = "rol", nullable = false)
    private Rol rol;

    // 1 = activo, 0 = desactivado
    @Column(name = "activo", nullable = false)
    private Boolean activo;

    // Valores posibles del campo rol, coinciden con el ENUM de MySQL
    public enum Rol {
        EMPLEADO, ADMINISTRADOR, GERENTE
    }
}

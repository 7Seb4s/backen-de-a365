package com.backdea365.app.model;

import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;

// Mapea la tabla reset_password donde se guardan los codigos de recuperacion
@Data
@Entity
@Table(name = "reset_password")
public class ResetPassword {

    // ID autoincremental
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    // Correo del usuario que solicito recuperar contrasena
    @Column(name = "correo", nullable = false)
    private String correo;

    // Codigo de 6 digitos generado aleatoriamente
    @Column(name = "codigo", nullable = false)
    private String codigo;

    // Fecha y hora en que el codigo deja de ser valido (15 minutos desde creacion)
    @Column(name = "expiracion", nullable = false)
    private LocalDateTime expiracion;

    // false = todavia puede usarse, true = ya fue usado o invalidado
    @Column(name = "usado", nullable = false)
    private Boolean usado = false;

    // Fecha y hora en que se creo el codigo
    @Column(name = "creado_en", nullable = false)
    private LocalDateTime creadoEn = LocalDateTime.now();
}

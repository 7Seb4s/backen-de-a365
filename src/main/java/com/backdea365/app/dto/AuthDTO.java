package com.backdea365.app.dto;

import lombok.Data;
import lombok.AllArgsConstructor;
import jakarta.validation.constraints.NotBlank;

// Define los datos que entran y salen del endpoint de login
public class AuthDTO {

    // Lo que el frontend envia al hacer login
    @Data
    public static class LoginRequest {
        @NotBlank(message = "El codigo es obligatorio")
        private String codigo;

        @NotBlank(message = "La contrasena es obligatoria")
        private String password;
    }

    // Lo que el backend responde si el login es exitoso
    @Data
    @AllArgsConstructor
    public static class LoginResponse {
        private String token;    // JWT firmado con HS512
        private String tipo;     // siempre "Bearer"
        private Integer id;      // ID del usuario en la BD
        private String codigo;   // codigo del trabajador (ej: EMP001)
        private String nombre;   // nombre completo desde usuario_detalle
        private String rol;      // EMPLEADO, ADMINISTRADOR o GERENTE
        private String fotoUrl;  // URL de la foto de perfil (puede ser null)
    }
}

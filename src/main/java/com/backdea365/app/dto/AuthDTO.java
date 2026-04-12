package com.backdea365.app.dto;

// -------------------------------------------------------------
// AuthDTO.java
// Define la forma de los datos que entran y salen del endpoint
// de autenticacion. DTO = Data Transfer Object.
// -------------------------------------------------------------

import lombok.Data;
import lombok.AllArgsConstructor;
import jakarta.validation.constraints.NotBlank;

public class AuthDTO {

    // -- Lo que el frontend envia al hacer login ---------------
    @Data
    public static class LoginRequest {

        @NotBlank(message = "El codigo es obligatorio")
        private String codigo;

        @NotBlank(message = "La contrasena es obligatoria")
        private String password;
    }

    // -- Lo que el backend responde si el login es exitoso -----
    @Data
    @AllArgsConstructor
    public static class LoginResponse {
        private String token;    // Token JWT firmado con HS512
        private String tipo;     // Siempre "Bearer"
        private Integer id;      // ID interno del usuario en la BD
        private String codigo;   // Codigo del trabajador (ej: EMP001)
        private String nombre;   // Nombre completo desde usuario_detalle
        private String rol;      // EMPLEADO, ADMINISTRADOR o GERENTE
    }
}

package com.backdea365.app.dto;

import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

// DTOs para perfil del usuario logueado
// Alineados con sp_perfil_obtener, sp_perfil_actualizar y sp_cambiar_clave
public class PerfilDTO {

    // ── GET /api/perfil ──
    // Coincide con las columnas que devuelve sp_perfil_obtener
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PerfilResponse {
        private String codigoTrabajador;
        private String nombreCompleto;
        private String correo;
        private String direccion;
        private String telefono;
        private String dni;
        private String fotoUrl; // URL publica de la foto de perfil (puede ser null)
    }

    // ── PUT /api/perfil ──
    @Data
    public static class ActualizarRequest {

        @NotBlank(message = "El nombre completo es obligatorio")
        @Pattern(
                regexp = "^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ ]+$",
                message = "El nombre solo puede contener letras y espacios"
        )
        @Size(min = 2, max = 120, message = "El nombre debe tener entre 2 y 120 caracteres")
        private String nombreCompleto;

        @NotBlank(message = "El correo es obligatorio")
        @Email(message = "El correo no es valido")
        @Size(max = 120)
        private String correo;

        @Size(max = 150, message = "La direccion no puede superar 150 caracteres")
        private String direccion;

        @NotBlank(message = "El telefono es obligatorio")
        @Pattern(regexp = "^[+\\d\\s]{9,30}$", message = "El telefono no tiene un formato valido")
        private String telefono;

        @NotBlank(message = "El DNI es obligatorio")
        @Pattern(regexp = "^\\d{8}$", message = "El DNI debe tener exactamente 8 digitos")
        private String dni;
    }

    // ── PUT /api/perfil/contrasena ──
    // Politica de contrasena: min 8 chars, 1 mayuscula, 1 digito, 1 especial
    @Data
    public static class CambiarContrasenaRequest {

        @NotBlank(message = "La contrasena actual es obligatoria")
        private String contrasenaActual;

        @NotBlank(message = "La nueva contrasena es obligatoria")
        @Size(min = 8, message = "La contrasena debe tener al menos 8 caracteres")
        @Pattern(
                regexp = "^(?=.*[A-Z])(?=.*\\d)(?=.*[^A-Za-z0-9]).+$",
                message = "La contrasena debe contener al menos 1 mayuscula, 1 digito y 1 caracter especial"
        )
        private String nuevaContrasena;

        @NotBlank(message = "Debes confirmar la nueva contrasena")
        private String confirmarContrasena;
    }

    // ── Respuesta generica para operaciones sobre perfil/contrasena ──
    @Data
    @AllArgsConstructor
    public static class OperacionResponse {
        private String mensaje;
    }

    // ── PUT /api/perfil/foto ──
    @Data
    @AllArgsConstructor
    public static class FotoResponse {
        private String mensaje;
        private String fotoUrl; // URL publica para acceder a la foto
    }
}

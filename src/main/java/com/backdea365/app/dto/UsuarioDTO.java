package com.backdea365.app.dto;

import jakarta.validation.constraints.*;
import lombok.Data;

// DTOs para creación y respuesta de usuario
public class UsuarioDTO {

    @Data
    public static class CrearRequest {

        @NotBlank(message = "El nombre completo es obligatorio")
        @Pattern(
                regexp = "^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ ]+$",
                message = "El nombre solo puede contener letras y espacios"
        )
        @Size(min = 2, max = 120, message = "El nombre debe tener entre 2 y 120 caracteres")
        private String nombreCompleto;

        @NotBlank(message = "El apellido completo es obligatorio")
        @Pattern(
                regexp = "^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ ]+$",
                message = "El apellido solo puede contener letras y espacios"
        )
        @Size(min = 2, max = 120, message = "El apellido debe tener entre 2 y 120 caracteres")
        private String apellidoCompleto;

        @NotBlank(message = "El DNI es obligatorio")
        @Pattern(regexp = "^\\d{8}$", message = "El DNI debe tener exactamente 8 dígitos")
        private String dni;

        @NotBlank(message = "El teléfono es obligatorio")
        @Pattern(regexp = "^\\d{9}$", message = "El teléfono debe tener exactamente 9 dígitos")
        private String telefono;

        @NotBlank(message = "El correo es obligatorio")
        @Email(message = "El correo no es válido")
        private String correo;

        @NotBlank(message = "La contraseña es obligatoria")
        @Size(min = 6, message = "La contraseña debe tener al menos 6 caracteres")
        private String contrasena;

        @NotNull(message = "El rol es obligatorio")
        private String rol; // EMPLEADO, ADMINISTRADOR, GERENTE
    }

    @Data
    public static class CrearResponse {
        private Integer id;
        private String codigo;
        private String nombreCompleto;
        private String rol;
        private String mensaje;

        public CrearResponse(Integer id, String codigo, String nombreCompleto, String rol) {
            this.id             = id;
            this.codigo         = codigo;
            this.nombreCompleto = nombreCompleto;
            this.rol            = rol;
            this.mensaje        = "Usuario creado exitosamente";
        }
    }
}
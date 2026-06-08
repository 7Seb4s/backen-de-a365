package com.backdena365.app.dto;

import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

// DTOs para creación, respuesta y panel de usuarios (solo admin/gerente)
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

        // Política de contraseña:
        // - al menos 8 caracteres
        // - al menos 1 mayúscula
        // - al menos 1 dígito
        // - al menos 1 carácter especial (cualquier no-alfanumérico)
        @NotBlank(message = "La contraseña es obligatoria")
        @Size(min = 8, message = "La contraseña debe tener al menos 8 caracteres")
        @Pattern(
                regexp = "^(?=.*[A-Z])(?=.*\\d)(?=.*[^A-Za-z0-9]).+$",
                message = "La contraseña debe contener al menos 1 mayúscula, 1 dígito y 1 carácter especial"
        )
        private String contrasena;

        @NotNull(message = "El rol es obligatorio")
        private String rol; // EMPLEADO, ADMINISTRADOR, GERENTE
    }

    @Data
    public static class CrearResponse {
        private Integer id;
        private String  codigo;
        private String  nombreCompleto;
        private String  rol;
        private String  mensaje;

        public CrearResponse(Integer id, String codigo, String nombreCompleto, String rol) {
            this.id             = id;
            this.codigo         = codigo;
            this.nombreCompleto = nombreCompleto;
            this.rol            = rol;
            this.mensaje        = "Usuario creado exitosamente";
        }
    }

    // ── Ítem del panel de usuarios del admin ──
    // Usado por GET /api/usuarios y GET /api/usuarios/eliminados
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PanelItem {
        private Integer id;
        private String  nombre;
        private String  dni;
        private String  cargo;   // rol formateado legible (ej: "Gerente general")
        private String  codigo;
        private String  correo;
        private String  rol;     // valor raw del ENUM (ej: "GERENTE")
    }
}

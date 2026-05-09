package com.backdea365.app.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

// Define los datos de entrada para cada paso del flujo de recuperacion
public class RecuperarDTO {

    // Paso 1: el usuario envia su correo para recibir el codigo
    @Data
    public static class SolicitarRequest {
        @NotBlank @Email
        private String correo;
    }

    // Paso 2: el usuario envia el correo + el codigo que recibio
    @Data
    public static class VerificarRequest {
        @NotBlank @Email
        private String correo;
        @NotBlank @Size(min = 6, max = 6)
        private String codigo;
    }

    // Paso 3: el usuario envia correo + codigo + nueva contrasena
    @Data
    public static class CambiarRequest {
        @NotBlank @Email
        private String correo;
        @NotBlank @Size(min = 6, max = 6)
        private String codigo;
        @NotBlank @Size(min = 6)
        private String nuevaPassword;
    }
}

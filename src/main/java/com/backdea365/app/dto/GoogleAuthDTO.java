package com.backdea365.app.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

// Define los datos que llegan del frontend al hacer login con Google
public class GoogleAuthDTO {

    // El frontend envia el credential que devuelve Google Sign-In
    @Data
    public static class GoogleLoginRequest {
        @NotBlank(message = "El token de Google es obligatorio")
        private String credential; // ID Token generado por Google
    }
}

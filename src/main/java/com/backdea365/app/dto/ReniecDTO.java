package com.backdea365.app.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

// DTOs para la consulta de datos personales por DNI contra la API de Decolecta (RENIEC)
public class ReniecDTO {

    // Respuesta cruda de la API de Decolecta (campos en snake_case)
    @Data
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ApiResponse {
        @JsonProperty("first_name")       private String firstName;       // Nombres
        @JsonProperty("first_last_name")  private String firstLastName;   // Apellido paterno
        @JsonProperty("second_last_name") private String secondLastName;  // Apellido materno
        @JsonProperty("full_name")        private String fullName;        // Nombre completo
        @JsonProperty("document_number")  private String documentNumber;  // DNI
    }

    // Datos ya mapeados que se devuelven al frontend para autocompletar el formulario
    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class Persona {
        private String dni;
        private String nombres;          // -> campo "nombreCompleto" del formulario
        private String apellidoPaterno;
        private String apellidoMaterno;
        private String apellidos;        // paterno + materno -> campo "apellidoCompleto" del formulario
        private String nombreCompleto;   // full_name tal cual lo entrega RENIEC
    }
}

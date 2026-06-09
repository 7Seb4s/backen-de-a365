package com.backdea365.app.controller;

import com.backdea365.app.dto.AuthDTO;
import com.backdea365.app.dto.GoogleAuthDTO;
import com.backdea365.app.service.ServicioGoogleAuth;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
public class ControladorGoogleAuthTest {

    private MockMvc mockMvc;

    @Mock
    private ServicioGoogleAuth servicioGoogleAuth;

    @InjectMocks
    private ControladorGoogleAuth controladorGoogleAuth;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    public void setUp() {
        // Inicialización del entorno MockMvc aislado para Google Auth
        mockMvc = MockMvcBuilders.standaloneSetup(controladorGoogleAuth).build();
    }

    @Test
    public void testLoginConGoogle_TokenValido_RetornaJWTResponseYStatus200() throws Exception {
        // Arrange: Se simula la llegada del ID Token (credential) desde el frontend
        GoogleAuthDTO.GoogleLoginRequest req = new GoogleAuthDTO.GoogleLoginRequest();
        req.setCredential("eyJhbGciOiJSUzI1NiIsImtpZCI6ImY4N...GoogleIdTokenReal2026");

        // Respuesta esperada: Intercambio exitoso por un JWT de IMPULSA A365 S.A.C.
        AuthDTO.LoginResponse resp = new AuthDTO.LoginResponse(
                "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJTVVAtNDUxMiIsImV4cCI6MTc4MDk4MjQwMH0.internalJwtToken",
                "Bearer",
                12,
                "SUP-4512",
                "Erik Smit Ventura Hernandez",
                "ADMINISTRADOR"
        );

        // Mockeo del servicio pasando la cadena de credenciales exacta extraída de la petición
        when(servicioGoogleAuth.loginConGoogle(anyString())).thenReturn(resp);

        // Act & Assert: Simulación del POST y validación del mapeo JSON unificado
        mockMvc.perform(post("/api/auth/google")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJTVVAtNDUxMiIsImV4cCI6MTc4MDk4MjQwMH0.internalJwtToken"))
                .andExpect(jsonPath("$.tipo").value("Bearer"))
                .andExpect(jsonPath("$.id").value(12))
                .andExpect(jsonPath("$.codigo").value("SUP-4512"))
                .andExpect(jsonPath("$.nombre").value("Erik Smit Ventura Hernandez"))
                .andExpect(jsonPath("$.rol").value("ADMINISTRADOR"));
    }
}
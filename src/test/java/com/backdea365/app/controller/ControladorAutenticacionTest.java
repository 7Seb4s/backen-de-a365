package com.backdea365.app.controller;

import com.backdea365.app.dto.AuthDTO;
import com.backdea365.app.service.ServicioAutenticacion;
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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
public class ControladorAutenticacionTest {

    private MockMvc mockMvc;

    @Mock
    private ServicioAutenticacion servicioAuth;

    @InjectMocks
    private ControladorAutenticacion controladorAutenticacion;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    public void setUp() {
        // Inicialización aislada de MockMvc para el controlador de seguridad
        mockMvc = MockMvcBuilders.standaloneSetup(controladorAutenticacion).build();
    }

    @Test
    public void testLogin_CredencialesCorrectas_RetornaTokenYStatus200() throws Exception {
        // Arrange: Preparación de la petición de entrada simulada
        AuthDTO.LoginRequest req = new AuthDTO.LoginRequest();
        req.setCodigo("SUP-4512");
        req.setPassword("Password2026*");

        // Respuesta esperada del token firmado con HS512 y datos de sesión
        AuthDTO.LoginResponse resp = new AuthDTO.LoginResponse(
                "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJTVVAtNDUxMiIsImV4cCI6MTc4MDk4MjQwMH0.mockToken123",
                "Bearer",
                12,
                "SUP-4512",
                "Erik Smit Ventura Hernandez",
                "ADMINISTRADOR",
                null // fotoUrl
        );

        when(servicioAuth.login(any(AuthDTO.LoginRequest.class))).thenReturn(resp);

        // Act & Assert: Simulación del POST y aserciones sobre el JSON de salida
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJTVVAtNDUxMiIsImV4cCI6MTc4MDk4MjQwMH0.mockToken123"))
                .andExpect(jsonPath("$.tipo").value("Bearer"))
                .andExpect(jsonPath("$.id").value(12))
                .andExpect(jsonPath("$.codigo").value("SUP-4512"))
                .andExpect(jsonPath("$.nombre").value("Erik Smit Ventura Hernandez"))
                .andExpect(jsonPath("$.rol").value("ADMINISTRADOR"));
    }
}
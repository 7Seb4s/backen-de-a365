package com.backdea365.app.controller;

import com.backdea365.app.dto.RecuperarDTO;
import com.backdea365.app.service.ServicioRecuperacion;
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
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
public class ControladorRecuperacionTest {

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @Mock
    private ServicioRecuperacion servicioRecuperacion;

    @InjectMocks
    private ControladorRecuperacion controladorRecuperacion;

    @BeforeEach
    public void setUp() {
        objectMapper = new ObjectMapper();

        // Configuración de MockMvc en entorno Standalone (rápido y aislado)
        mockMvc = MockMvcBuilders.standaloneSetup(controladorRecuperacion).build();
    }

    @Test
    public void testSolicitar_CorreoValido_DebeRetornarStatus200() throws Exception {
        // Arrange
        RecuperarDTO.SolicitarRequest request = new RecuperarDTO.SolicitarRequest();
        request.setCorreo("erik.ventura@impulsaa365.com");

        // Al ser un método void, configuramos doNothing
        doNothing().when(servicioRecuperacion).solicitarCodigo(any(RecuperarDTO.SolicitarRequest.class));

        // Act & Assert
        mockMvc.perform(post("/api/auth/recuperar/solicitar")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());

        // Verificamos que el servicio fue invocado exactamente 1 vez
        verify(servicioRecuperacion, times(1)).solicitarCodigo(any(RecuperarDTO.SolicitarRequest.class));
    }

    @Test
    public void testVerificar_CodigoYCorreoValidos_DebeRetornarStatus200() throws Exception {
        // Arrange
        RecuperarDTO.VerificarRequest request = new RecuperarDTO.VerificarRequest();
        request.setCorreo("erik.ventura@impulsaa365.com");
        request.setCodigo("485912"); // Exactamente 6 caracteres cumpliendo @Size(min = 6, max = 6)

        doNothing().when(servicioRecuperacion).verificarCodigo(any(RecuperarDTO.VerificarRequest.class));

        // Act & Assert
        mockMvc.perform(post("/api/auth/recuperar/verificar")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());

        verify(servicioRecuperacion, times(1)).verificarCodigo(any(RecuperarDTO.VerificarRequest.class));
    }

    @Test
    public void testCambiar_PayloadValido_DebeActualizarPasswordYRetornarStatus200() throws Exception {
        // Arrange
        RecuperarDTO.CambiarRequest request = new RecuperarDTO.CambiarRequest();
        request.setCorreo("erik.ventura@impulsaa365.com");
        request.setCodigo("485912");
        // Cumple la política: min 8 caracteres, 1 mayúscula, 1 dígito y 1 carácter especial
        request.setNuevaPassword("Impulsa2026@");

        doNothing().when(servicioRecuperacion).cambiarPassword(any(RecuperarDTO.CambiarRequest.class));

        // Act & Assert
        mockMvc.perform(post("/api/auth/recuperar/cambiar")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());

        verify(servicioRecuperacion, times(1)).cambiarPassword(any(RecuperarDTO.CambiarRequest.class));
    }
}

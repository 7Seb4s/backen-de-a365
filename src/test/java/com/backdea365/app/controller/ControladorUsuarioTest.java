package com.backdea365.app.controller;

import com.backdea365.app.dto.UsuarioDTO;
import com.backdea365.app.service.ServicioUsuario;
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

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
public class ControladorUsuarioTest {

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @Mock
    private ServicioUsuario servicioUsuario;

    @InjectMocks
    private ControladorUsuario controladorUsuario;

    @BeforeEach
    public void setUp() {
        objectMapper = new ObjectMapper();

        // Construcción del entorno MockMvc aislado para el controlador de usuarios
        mockMvc = MockMvcBuilders.standaloneSetup(controladorUsuario).build();
    }

    @Test
    public void testCrearUsuario_PayloadValido_DebeRetornarCrearResponseYStatus201() throws Exception {
        // Arrange
        UsuarioDTO.CrearRequest request = new UsuarioDTO.CrearRequest();
        request.setNombreCompleto("Erik Smit");
        request.setApellidoCompleto("Ventura Hernandez");
        request.setDni("74859612");         // Cumple: exactamente 8 dígitos
        request.setTelefono("987654321");    // Cumple: exactamente 9 dígitos
        request.setCorreo("erik.ventura@impulsaa365.com");
        request.setContrasena("Impulsa2026@"); // Cumple: min 8, 1 mayúscula, 1 dígito, 1 especial
        request.setRol("ADMINISTRADOR");

        UsuarioDTO.CrearResponse responseMock = new UsuarioDTO.CrearResponse(
                1,
                "ADM-001",
                "Erik Smit Ventura Hernandez",
                "ADMINISTRADOR"
        );

        when(servicioUsuario.crearUsuario(any(UsuarioDTO.CrearRequest.class))).thenReturn(responseMock);

        // Act & Assert
        mockMvc.perform(post("/api/usuarios/crear")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated()) // Valida el código de estado HTTP 201
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.codigo").value("ADM-001"))
                .andExpect(jsonPath("$.nombreCompleto").value("Erik Smit Ventura Hernandez"))
                .andExpect(jsonPath("$.rol").value("ADMINISTRADOR"))
                .andExpect(jsonPath("$.mensaje").value("Usuario creado exitosamente"));
    }

    @Test
    public void testListarActivos_DebeRetornarListaDeUsuariosYStatus200() throws Exception {
        // Arrange
        List<UsuarioDTO.PanelItem> listaMock = List.of(
                new UsuarioDTO.PanelItem(1, "Erik Smit", "74859612", "Administrador de TI", "ADM-001", "erik.ventura@impulsaa365.com", "ADMINISTRADOR")
        );

        when(servicioUsuario.listarActivos()).thenReturn(listaMock);

        // Act & Assert
        mockMvc.perform(get("/api/usuarios"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].id").value(1))
                .andExpect(jsonPath("$[0].nombre").value("Erik Smit"))
                .andExpect(jsonPath("$[0].cargo").value("Administrador de TI"))
                .andExpect(jsonPath("$[0].rol").value("ADMINISTRADOR"));
    }

    @Test
    public void testListarEliminados_DebeRetornarListaDeUsuariosDesactivadosYStatus200() throws Exception {
        // Arrange
        List<UsuarioDTO.PanelItem> listaMock = List.of(
                new UsuarioDTO.PanelItem(5, "Juan Perez", "00001111", "Ex Empleado", "EMP-045", "juan.perez@mail.com", "EMPLEADO")
        );

        when(servicioUsuario.listarEliminados()).thenReturn(listaMock);

        // Act & Assert
        mockMvc.perform(get("/api/usuarios/eliminados"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].id").value(5))
                .andExpect(jsonPath("$[0].nombre").value("Juan Perez"))
                .andExpect(jsonPath("$[0].cargo").value("Ex Empleado"))
                .andExpect(jsonPath("$[0].codigo").value("EMP-045"));
    }
}
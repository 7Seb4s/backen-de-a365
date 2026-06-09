package com.backdea365.app.controller;

import com.backdea365.app.dto.IncidenciaDTO;
import com.backdea365.app.security.ServicioDetalleUsuario;
import com.backdea365.app.service.ServicioIncidencia;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import java.util.List;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
public class ControladorIncidenciaTest {

    private MockMvc mockMvc;

    @Mock
    private ServicioIncidencia servicioIncidencia;

    @Mock
    private ServicioDetalleUsuario servicioDetalleUsuario;

    @Mock
    private UserDetails mockUserDetails;

    @InjectMocks
    private ControladorIncidencia controladorIncidencia;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    public void setUp() {
        // Creamos un resolver personalizado para inyectar automáticamente el mock de UserDetails
        HandlerMethodArgumentResolver mockAuthPrincipalResolver = new HandlerMethodArgumentResolver() {
            @Override
            public boolean supportsParameter(MethodParameter parameter) {
                return parameter.getParameterType().isAssignableFrom(UserDetails.class);
            }

            @Override
            public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer,
                                          NativeWebRequest webRequest, WebDataBinderFactory binderFactory) {
                return mockUserDetails;
            }
        };

        // Construcción de MockMvc inyectando nuestro resolver de seguridad customizado
        mockMvc = MockMvcBuilders.standaloneSetup(controladorIncidencia)
                .setCustomArgumentResolvers(mockAuthPrincipalResolver)
                .build();
    }

    @Test
    public void testListar_RetornaListaItemsResumenYStatus200() throws Exception {
        // Arrange: Definimos el mock del usuario localmente solo para este test que lo requiere
        when(mockUserDetails.getUsername()).thenReturn("SUP-4512");

        int idUsuarioSimulado = 12;
        IncidenciaDTO.ItemResumen item = new IncidenciaDTO.ItemResumen(
                101L,
                "Actualizacion",
                "Topic: Reconfiguración de colas de atención",
                true
        );

        when(servicioDetalleUsuario.obtenerIdPorCodigo("SUP-4512")).thenReturn(idUsuarioSimulado);
        when(servicioIncidencia.listar(idUsuarioSimulado)).thenReturn(List.of(item));

        // Act & Assert
        mockMvc.perform(get("/api/incidencias"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(101L))
                .andExpect(jsonPath("$[0].tipo").value("Actualizacion"))
                .andExpect(jsonPath("$[0].tema").value("Topic: Reconfiguración de colas de atención"))
                .andExpect(jsonPath("$[0].resaltado").value(true));
    }

    @Test
    public void testCrear_PeticionValida_RetornaOperacionResponseYStatus201() throws Exception {
        // Arrange: Definimos el mock del usuario localmente solo para este test que lo requiere
        when(mockUserDetails.getUsername()).thenReturn("SUP-4512");

        int idUsuarioSimulado = 12;
        IncidenciaDTO.CrearRequest req = new IncidenciaDTO.CrearRequest();
        req.setAsunto("Falla intermitente en reportería de llamadas de la cola");
        req.setTipo("INCIDENCIA_TECNICA");
        req.setNumeroTicket(5005);
        req.setContenido("No se guardan los tiempos de espera exactos de los asesores en los reportes.");

        IncidenciaDTO.OperacionResponse response = new IncidenciaDTO.OperacionResponse("Incidencia registrada con éxito");

        when(servicioDetalleUsuario.obtenerIdPorCodigo("SUP-4512")).thenReturn(idUsuarioSimulado);
        when(servicioIncidencia.crear(any(IncidenciaDTO.CrearRequest.class), eq(idUsuarioSimulado))).thenReturn(response);

        // Act & Assert
        mockMvc.perform(post("/api/incidencias")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.mensaje").value("Incidencia registrada con éxito"));
    }

    @Test
    public void testDetalle_IdValido_RetornaDetalleCompletoYStatus200() throws Exception {
        // Arrange: Este test no interactúa con mockUserDetails, por ende no arrojará UnnecessaryStubbingException
        Long idIncidencia = 250L;
        IncidenciaDTO.DetalleResponse detalle = new IncidenciaDTO.DetalleResponse(
                idIncidencia,
                "Caída del módulo de asignación manual de leads",
                "CRITICO",
                "El supervisor no puede mover registros entre campañas activas.",
                6006,
                "REPORTADA",
                "2026-06-08T14:20:00",
                "SUP-4512",
                "erik.ventura@impulsaa365.com"
        );

        when(servicioIncidencia.obtenerDetalle(idIncidencia)).thenReturn(detalle);

        // Act & Assert
        mockMvc.perform(get("/api/incidencias/{id}", idIncidencia))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(250L))
                .andExpect(jsonPath("$.asunto").value("Caída del módulo de asignación manual de leads"))
                .andExpect(jsonPath("$.numeroTicket").value(6006))
                .andExpect(jsonPath("$.estado").value("REPORTADA"))
                .andExpect(jsonPath("$.codigoUsuario").value("SUP-4512"))
                .andExpect(jsonPath("$.correoUsuario").value("erik.ventura@impulsaa365.com"));
    }
}
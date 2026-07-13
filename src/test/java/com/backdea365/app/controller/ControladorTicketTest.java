package com.backdea365.app.controller;

import com.backdea365.app.dto.TicketDTO;
import com.backdea365.app.security.ServicioDetalleUsuario;
import com.backdea365.app.service.ServicioTicket;
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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
public class ControladorTicketTest {

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @Mock
    private ServicioTicket servicioTicket;

    @Mock
    private ServicioDetalleUsuario servicioDetalleUsuario;

    @Mock
    private UserDetails userDetails;

    @InjectMocks
    private ControladorTicket controladorTicket;

    @BeforeEach
    public void setUp() {
        objectMapper = new ObjectMapper();

        // Resolver personalizado para interceptar e inyectar el mock de UserDetails en @AuthenticationPrincipal
        HandlerMethodArgumentResolver mockAuthPrincipalResolver = new HandlerMethodArgumentResolver() {
            @Override
            public boolean supportsParameter(MethodParameter parameter) {
                return parameter.getParameterType().isAssignableFrom(UserDetails.class);
            }

            @Override
            public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer,
                                          NativeWebRequest webRequest, WebDataBinderFactory binderFactory) {
                return userDetails;
            }
        };

        // Configuración de MockMvc en entorno Standalone controlado
        mockMvc = MockMvcBuilders.standaloneSetup(controladorTicket)
                .setCustomArgumentResolvers(mockAuthPrincipalResolver)
                .build();
    }

    @Test
    public void testListar_SinParametroTab_DebeUsarValorPorDefectoYRetornarStatus200() throws Exception {
        // Arrange
        String codigoTrabajadorMock = "AGENT-99";
        int idUsuarioSimulado = 45;

        when(userDetails.getUsername()).thenReturn(codigoTrabajadorMock);
        when(servicioDetalleUsuario.obtenerIdPorCodigo(codigoTrabajadorMock)).thenReturn(idUsuarioSimulado);

        List<TicketDTO.ItemResumen> listaMock = List.of(
                new TicketDTO.ItemResumen(1024, "EN_EVALUACION", "Sede Central", false)
        );
        // "pendientes" es el defaultValue indicado en el @RequestParam del controlador
        when(servicioTicket.listarPorTab("pendientes", idUsuarioSimulado)).thenReturn(listaMock);

        // Act & Assert
        mockMvc.perform(get("/api/tickets"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].numero").value(1024))
                .andExpect(jsonPath("$[0].estado").value("EN_EVALUACION"))
                .andExpect(jsonPath("$[0].locacion").value("Sede Central"))
                .andExpect(jsonPath("$[0].resaltado").value(false));
    }

    @Test
    public void testListar_ConTabEspecifico_DebeRetornarListaFiltradaYStatus200() throws Exception {
        // Arrange
        String codigoTrabajadorMock = "AGENT-99";
        int idUsuarioSimulado = 45;
        String tabSeleccionado = "completados";

        when(userDetails.getUsername()).thenReturn(codigoTrabajadorMock);
        when(servicioDetalleUsuario.obtenerIdPorCodigo(codigoTrabajadorMock)).thenReturn(idUsuarioSimulado);

        List<TicketDTO.ItemResumen> listaMock = List.of(
                new TicketDTO.ItemResumen(985, "EVALUACION_COMPLETADA", "Planta Industrial", true)
        );
        when(servicioTicket.listarPorTab(tabSeleccionado, idUsuarioSimulado)).thenReturn(listaMock);

        // Act & Assert
        mockMvc.perform(get("/api/tickets").param("tab", tabSeleccionado))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].numero").value(985))
                .andExpect(jsonPath("$[0].estado").value("EVALUACION_COMPLETADA"))
                .andExpect(jsonPath("$[0].resaltado").value(true));
    }

    @Test
    public void testDetalle_ConNumeroTicketValido_DebeRetornarDetalleCompletoYStatus200() throws Exception {
        // Arrange
        Integer numeroTicketParam = 2026;
        String codigoTrabajadorMock = "AGENT-99";
        int idUsuarioSimulado = 45;

        when(userDetails.getUsername()).thenReturn(codigoTrabajadorMock);
        when(servicioDetalleUsuario.obtenerIdPorCodigo(codigoTrabajadorMock)).thenReturn(idUsuarioSimulado);

        TicketDTO.DetalleResponse detalleMock = new TicketDTO.DetalleResponse(
                "Erik Smit Ventura", "Perú", 12, 2, "18:45", "1:05:22",
                "987654321", "erik.ventura@mail.com", "Perú", "Web Application", "Rapido",
                "#2026", "Soporte Técnico", "ALTA", "AGENT-99"
        );

        // Sin rol administrativo (getAuthorities vacío por defecto) -> puedeVerTodo = false
        when(servicioTicket.obtenerDetalle(numeroTicketParam, idUsuarioSimulado, false)).thenReturn(detalleMock);

        // Act & Assert
        mockMvc.perform(get("/api/tickets/{numero}", numeroTicketParam))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.usuarioNombre").value("Erik Smit Ventura"))
                .andExpect(jsonPath("$.tickets").value(12))
                .andExpect(jsonPath("$.ticketActivoId").value("#2026"))
                .andExpect(jsonPath("$.prioridad").value("ALTA"))
                .andExpect(jsonPath("$.asignadoA").value("AGENT-99"));
    }

    @Test
    public void testCrear_PayloadValido_DebeCrearTicketYRetornarStatus21() throws Exception {
        // Arrange
        String codigoTrabajadorMock = "AGENT-99";
        int idUsuarioSimulado = 45;

        when(userDetails.getUsername()).thenReturn(codigoTrabajadorMock);
        when(servicioDetalleUsuario.obtenerIdPorCodigo(codigoTrabajadorMock)).thenReturn(idUsuarioSimulado);

        TicketDTO.CrearRequest request = new TicketDTO.CrearRequest(
                "Fallo de conexión en servidor",
                "Área TI",
                "No hay acceso a la BD principal",
                "ALTA"
        );

        TicketDTO.ItemResumen itemCreadoMock = new TicketDTO.ItemResumen(1025, "PENDIENTE", "Área TI", false);
        when(servicioTicket.crear(any(TicketDTO.CrearRequest.class), eq(idUsuarioSimulado))).thenReturn(itemCreadoMock);

        // Act & Assert
        mockMvc.perform(post("/api/tickets")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated()) // Valida explícitamente el código de respuesta HTTP 201
                .andExpect(jsonPath("$.numero").value(1025))
                .andExpect(jsonPath("$.estado").value("PENDIENTE"))
                .andExpect(jsonPath("$.locacion").value("Área TI"));
    }
}
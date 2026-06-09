package com.backdea365.app.controller;

import com.backdea365.app.dto.InicioDTO;
import com.backdea365.app.security.ServicioDetalleUsuario;
import com.backdea365.app.service.ServicioInicio;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.MethodParameter;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import java.time.LocalDate;
import java.util.List;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
public class ControladorInicioTest {

    private MockMvc mockMvc;

    @Mock
    private ServicioInicio servicioInicio;

    @Mock
    private ServicioDetalleUsuario servicioDetalleUsuario;

    @Mock
    private UserDetails mockUserDetails;

    @InjectMocks
    private ControladorInicio controladorInicio;

    @BeforeEach
    public void setUp() {
        // Resolvedor de argumentos personalizado para interceptar e inyectar el mock de UserDetails
        // en el parámetro @AuthenticationPrincipal del controlador.
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

        // Construcción del entorno MockMvc en modo Standalone
        mockMvc = MockMvcBuilders.standaloneSetup(controladorInicio)
                .setCustomArgumentResolvers(mockAuthPrincipalResolver)
                .build();
    }

    @Test
    public void testResumen_UsuarioAutenticado_RetornaConteoDeTicketsYStatus200() throws Exception {
        // Arrange
        when(mockUserDetails.getUsername()).thenReturn("SUP-4512");
        int idUsuarioSimulado = 12;

        InicioDTO.ResumenTickets resumenMock = new InicioDTO.ResumenTickets(5, 14, 2);

        when(servicioDetalleUsuario.obtenerIdPorCodigo("SUP-4512")).thenReturn(idUsuarioSimulado);
        when(servicioInicio.obtenerResumen(idUsuarioSimulado)).thenReturn(resumenMock);

        // Act & Assert
        mockMvc.perform(get("/api/inicio/resumen"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ticketsPendientes").value(5))
                .andExpect(jsonPath("$.ticketsAtendidos").value(14))
                .andExpect(jsonPath("$.ticketsCancelados").value(2));
    }

    @Test
    public void testTicketActivo_TieneTicketAsignado_RetornaDetalleTicketActivoYStatus200() throws Exception {
        // Arrange
        when(mockUserDetails.getUsername()).thenReturn("SUP-4512");
        int idUsuarioSimulado = 12;

        InicioDTO.TicketActivo ticketMock = new InicioDTO.TicketActivo(
                850L,
                4021,
                "Soporte Técnico",
                "ALTA",
                "EN_PROCESO",
                "SUP-4512"
        );

        when(servicioDetalleUsuario.obtenerIdPorCodigo("SUP-4512")).thenReturn(idUsuarioSimulado);
        when(servicioInicio.obtenerTicketActivo(idUsuarioSimulado)).thenReturn(ticketMock);

        // Act & Assert
        mockMvc.perform(get("/api/inicio/ticket-activo"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.idTicket").value(850L))
                .andExpect(jsonPath("$.numeroTicket").value(4021))
                .andExpect(jsonPath("$.tipoTicket").value("Soporte Técnico"))
                .andExpect(jsonPath("$.prioridad").value("ALTA"))
                .andExpect(jsonPath("$.estado").value("EN_PROCESO"))
                .andExpect(jsonPath("$.codigoAsignado").value("SUP-4512"));
    }

    @Test
    public void testActividad_IdTicketValido_RetornaUltimasAccionesSinRequerirAutenticacion() throws Exception {
        // Arrange
        // Este endpoint no usa UserDetails, por lo tanto no se define "when(mockUserDetails...)" aquí.
        // Esto previene por completo el error UnnecessaryStubbingException.
        Long idTicket = 850L;
        List<InicioDTO.ActividadItem> actividadesMock = List.of(
                new InicioDTO.ActividadItem("Ticket escalado al área de TI por el supervisor", "2026-06-08T11:15:00"),
                new InicioDTO.ActividadItem("Apertura y asignación automática del flujo", "2026-06-08T10:00:00")
        );

        when(servicioInicio.obtenerActividad(idTicket)).thenReturn(actividadesMock);

        // Act & Assert
        mockMvc.perform(get("/api/inicio/actividad/{idTicket}", idTicket))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[0].descripcion").value("Ticket escalado al área de TI por el supervisor"))
                .andExpect(jsonPath("$[1].descripcion").value("Apertura y asignación automática del flujo"));
    }

    @Test
    public void testCalendario_ConParametrosExplicitos_RetornaDiasConTicketsYStatus200() throws Exception {
        // Arrange
        when(mockUserDetails.getUsername()).thenReturn("SUP-4512");
        int idUsuarioSimulado = 12;
        int anioParam = 2026;
        int mesParam = 5;

        List<InicioDTO.CalendarioDia> diasMock = List.of(
                new InicioDTO.CalendarioDia("2026-05-12", 3),
                new InicioDTO.CalendarioDia("2026-05-20", 1)
        );

        when(servicioDetalleUsuario.obtenerIdPorCodigo("SUP-4512")).thenReturn(idUsuarioSimulado);
        when(servicioInicio.obtenerCalendario(idUsuarioSimulado, anioParam, mesParam)).thenReturn(diasMock);

        // Act & Assert
        mockMvc.perform(get("/api/inicio/calendario")
                        .param("anio", String.valueOf(anioParam))
                        .param("mes", String.valueOf(mesParam)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[0].dia").value("2026-05-12"))
                .andExpect(jsonPath("$[0].cantidad").value(3));
    }

    @Test
    public void testCalendario_SinParametros_CalculaFechaActualYRetornaStatus200() throws Exception {
        // Arrange
        when(mockUserDetails.getUsername()).thenReturn("SUP-4512");
        int idUsuarioSimulado = 12;

        // Se replica exactamente la lógica por defecto del controlador usando la fecha del sistema actual
        LocalDate hoy = LocalDate.now();
        int anioActual = hoy.getYear();
        int mesActual = hoy.getMonthValue();

        List<InicioDTO.CalendarioDia> diasMock = List.of(
                new InicioDTO.CalendarioDia(hoy.toString(), 2)
        );

        when(servicioDetalleUsuario.obtenerIdPorCodigo("SUP-4512")).thenReturn(idUsuarioSimulado);
        when(servicioInicio.obtenerCalendario(idUsuarioSimulado, anioActual, mesActual)).thenReturn(diasMock);

        // Act & Assert
        mockMvc.perform(get("/api/inicio/calendario"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].dia").value(hoy.toString()))
                .andExpect(jsonPath("$[0].cantidad").value(2));
    }
}
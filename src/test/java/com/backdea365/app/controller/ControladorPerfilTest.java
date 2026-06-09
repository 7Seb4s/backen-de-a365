package com.backdea365.app.controller;

import com.backdea365.app.dto.PerfilDTO;
import com.backdea365.app.security.ServicioDetalleUsuario;
import com.backdea365.app.service.ServicioPerfil;
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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
public class ControladorPerfilTest {

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @Mock
    private ServicioPerfil servicioPerfil;

    @Mock
    private ServicioDetalleUsuario servicioDetalleUsuario;

    @Mock
    private UserDetails userDetails;

    @InjectMocks
    private ControladorPerfil controladorPerfil;

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

        // Construcción aislada de MockMvc con soporte para el Principal autenticado
        mockMvc = MockMvcBuilders.standaloneSetup(controladorPerfil)
                .setCustomArgumentResolvers(mockAuthPrincipalResolver)
                .build();
    }

    @Test
    public void testObtener_DebeRetornarDatosDelPerfilYStatus200() throws Exception {
        // Arrange
        String codigoTrabajadorMock = "EMP-7845";
        int idUsuarioSimulado = 25;

        when(userDetails.getUsername()).thenReturn(codigoTrabajadorMock);
        when(servicioDetalleUsuario.obtenerIdPorCodigo(codigoTrabajadorMock)).thenReturn(idUsuarioSimulado);

        PerfilDTO.PerfilResponse perfilMock = new PerfilDTO.PerfilResponse(
                codigoTrabajadorMock,
                "Erik Smit Ventura Hernandez",
                "erik.ventura@impulsaa365.com",
                "Av. Universitaria 1230",
                "987654321",
                "74859612"
        );
        when(servicioPerfil.obtenerPerfil(idUsuarioSimulado)).thenReturn(perfilMock);

        // Act & Assert
        mockMvc.perform(get("/api/perfil"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.codigoTrabajador").value(codigoTrabajadorMock))
                .andExpect(jsonPath("$.nombreCompleto").value("Erik Smit Ventura Hernandez"))
                .andExpect(jsonPath("$.correo").value("erik.ventura@impulsaa365.com"))
                .andExpect(jsonPath("$.direccion").value("Av. Universitaria 1230"))
                .andExpect(jsonPath("$.telefono").value("987654321"))
                .andExpect(jsonPath("$.dni").value("74859612"));
    }

    @Test
    public void testActualizar_DatosValidos_DebeRetornarOperacionResponseYStatus200() throws Exception {
        // Arrange
        String codigoTrabajadorMock = "EMP-7845";
        int idUsuarioSimulado = 25;

        when(userDetails.getUsername()).thenReturn(codigoTrabajadorMock);
        when(servicioDetalleUsuario.obtenerIdPorCodigo(codigoTrabajadorMock)).thenReturn(idUsuarioSimulado);

        // Construimos la petición cumpliendo las expresiones regulares de tu DTO
        PerfilDTO.ActualizarRequest request = new PerfilDTO.ActualizarRequest();
        request.setNombreCompleto("Erik Smit Ventura Hernandez");
        request.setCorreo("erik.ventura@impulsaa365.com");
        request.setDireccion("Calle Los Olivos 452");
        request.setTelefono("912345678");
        request.setDni("70605040");

        PerfilDTO.OperacionResponse responseMock = new PerfilDTO.OperacionResponse("Perfil actualizado correctamente");
        when(servicioPerfil.actualizarPerfil(eq(idUsuarioSimulado), any(PerfilDTO.ActualizarRequest.class)))
                .thenReturn(responseMock);

        // Act & Assert
        mockMvc.perform(put("/api/perfil")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mensaje").value("Perfil actualizado correctamente"));
    }

    @Test
    public void testCambiarContrasena_DatosValidos_DebeRetornarOperacionResponseYStatus200() throws Exception {
        // Arrange
        String codigoTrabajadorMock = "EMP-7845";
        int idUsuarioSimulado = 25;

        when(userDetails.getUsername()).thenReturn(codigoTrabajadorMock);
        when(servicioDetalleUsuario.obtenerIdPorCodigo(codigoTrabajadorMock)).thenReturn(idUsuarioSimulado);

        // Cumple con la política de clave: min 8 caracteres, 1 mayúscula, 1 dígito y 1 especial (@)
        PerfilDTO.CambiarContrasenaRequest request = new PerfilDTO.CambiarContrasenaRequest();
        request.setContrasenaActual("ClaveAnterior123!");
        request.setNuevaContrasena("Impulsa2026@");
        request.setConfirmarContrasena("Impulsa2026@");

        PerfilDTO.OperacionResponse responseMock = new PerfilDTO.OperacionResponse("Contraseña cambiada con éxito");
        when(servicioPerfil.cambiarContrasena(eq(idUsuarioSimulado), any(PerfilDTO.CambiarContrasenaRequest.class)))
                .thenReturn(responseMock);

        // Act & Assert
        mockMvc.perform(put("/api/perfil/contrasena")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mensaje").value("Contraseña cambiada con éxito"));
    }
}
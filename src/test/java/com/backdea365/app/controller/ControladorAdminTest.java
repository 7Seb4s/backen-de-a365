package com.backdea365.app.controller;

import com.backdea365.app.dto.AdminDTO;
import com.backdea365.app.security.ServicioDetalleUsuario;
import com.backdea365.app.service.ServicioAdmin;
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

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
public class ControladorAdminTest {

    private MockMvc mockMvc;

    @Mock
    private ServicioAdmin servicioAdmin;

    @Mock
    private ServicioDetalleUsuario servicioDetalleUsuario;

    @InjectMocks
    private ControladorAdmin controladorAdmin;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    public void setUp() {
        // Inicialización del entorno MockMvc de forma aislada
        mockMvc = MockMvcBuilders.standaloneSetup(controladorAdmin).build();
    }

    @Test
    public void testTablero_RetornaListaYStatus200() throws Exception {
        // Arrange: Basado exactamente en el orden del constructor de TableroTicketItem
        // (Integer numeroTicket, String asunto, String actualizadoEn, String estado, String subestado, String previewUltimoMensaje)
        AdminDTO.TableroTicketItem item = new AdminDTO.TableroTicketItem(
                1001,
                "Falla de conexión en Discador Predictivo - Campaña Claro",
                "2026-06-08T15:30:00",
                "EN_REVISION",
                "CRITICO",
                "Se detectó una latencia alta en las colas de llamadas salientes.",
                3
        );
        when(servicioAdmin.obtenerColumnaTablero(eq("EN_REVISION"), any())).thenReturn(List.of(item));

        // Act & Assert
        mockMvc.perform(get("/api/admin/tablero")
                        .param("columna", "EN_REVISION")
                        .param("texto", ""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].numeroTicket").value(1001))
                .andExpect(jsonPath("$[0].asunto").value("Falla de conexión en Discador Predictivo - Campaña Claro"))
                .andExpect(jsonPath("$[0].estado").value("EN_REVISION"))
                .andExpect(jsonPath("$[0].previewUltimoMensaje").value("Se detectó una latencia alta en las colas de llamadas salientes."));
    }

    @Test
    public void testModalTicket_RetornaDetalleYStatus200() throws Exception {
        // Arrange: Instanciación exacta basada en los 15 atributos de TicketDetalle de tu clase AdminDTO
        AdminDTO.TicketDetalle detalle = new AdminDTO.TicketDetalle(
                1L,                                                   // idTicket
                2002,                                                 // numeroTicket
                "Acceso bloqueado a la plataforma CRM de Cobranzas",  // asunto
                "El asesor no puede autenticarse con sus credenciales activas.", // descripcion
                "SOPORTE TI",                                         // tipoTicket
                "ALTA",                                               // prioridad
                "EN_REVISION",                                        // estado
                "NINGUNO",                                            // subestado
                "Mesa de Ayuda - Sede Central",                       // locacionArea
                "2026-06-08T09:00:00",                                // creadoEn
                "2026-06-08T09:15:00",                                // actualizadoEn
                "SUP-4512",                                           // codigoSolicitante
                "Erik Smit Ventura Hernandez",                        // solicitadoPor (Coincide con tu JSON Path real)
                "TI-991",                                             // codigoAsignado
                "Operador Soporte Nivel 1"                            // asignadoA
        );
        when(servicioAdmin.obtenerModalTicket(2002)).thenReturn(detalle);

        // Act & Assert: Evaluando los nombres exactos de las variables de tu DTO
        mockMvc.perform(get("/api/admin/tickets/{numero}/modal", 2002))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.numeroTicket").value(2002))
                .andExpect(jsonPath("$.solicitadoPor").value("Erik Smit Ventura Hernandez"))
                .andExpect(jsonPath("$.codigoSolicitante").value("SUP-4512"))
                .andExpect(jsonPath("$.tipoTicket").value("SOPORTE TI"))
                .andExpect(jsonPath("$.locacionArea").value("Mesa de Ayuda - Sede Central"));
    }

    @Test
    public void testMoverTicket_RetornaOperacionResponseYStatus200() throws Exception {
        // Arrange: Uso del setter de MoverTicketRequest
        AdminDTO.MoverTicketRequest req = new AdminDTO.MoverTicketRequest();
        req.setColumna("EN_PROCESO_ATENCION");

        AdminDTO.OperacionResponse response = new AdminDTO.OperacionResponse("Ticket movido correctamente");
        when(servicioAdmin.moverTicket(eq(1001), any(AdminDTO.MoverTicketRequest.class))).thenReturn(response);

        // Act & Assert
        mockMvc.perform(put("/api/admin/tickets/{numero}/mover", 1001)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mensaje").value("Ticket movido correctamente"));
    }

    @Test
    public void testCrearTicket_RetornaStatus201() throws Exception {
        // Arrange: Uso de setters de CrearTicketAdminRequest
        AdminDTO.CrearTicketAdminRequest req = new AdminDTO.CrearTicketAdminRequest();
        req.setNumeroTicket(3003);
        req.setAsunto("Caída masiva de Troncal SIP de telefonía");
        req.setPrioridad("ALTA");
        req.setTipoTicket("INFRAESTRUCTURA");
        req.setIdSolicitante(10);
        req.setIdAsignado(2);
        req.setContenidoInicial("Llamadas entrantes se caen a los 3 segundos de ser contestadas.");

        AdminDTO.OperacionResponse response = new AdminDTO.OperacionResponse("Ticket creado correctamente");
        when(servicioAdmin.crearTicketAdmin(any(AdminDTO.CrearTicketAdminRequest.class))).thenReturn(response);

        // Act & Assert
        mockMvc.perform(post("/api/admin/tickets")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.mensaje").value("Ticket creado correctamente"));
    }
}
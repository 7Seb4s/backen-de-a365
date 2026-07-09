package com.backdea365.app.controller;

import com.backdea365.app.dto.TecnicoDTO;
import com.backdea365.app.service.ServicioTecnico;
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

import java.util.Collections;
import java.util.List;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

// Pruebas unitarias para ControladorTecnico
// Cubre los 6 endpoints: listar/aprobar/rechazar tickets, listar/asignar/rechazar incidencias
@ExtendWith(MockitoExtension.class)
public class ControladorTecnicoTest {

    private MockMvc mockMvc;

    @Mock
    private ServicioTecnico servicioTecnico;

    @InjectMocks
    private ControladorTecnico controladorTecnico;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    public void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(controladorTecnico).build();
    }

    // ═══════════════════════════════════════════════════
    //  TICKETS
    // ═══════════════════════════════════════════════════

    @Test
    public void listarTickets_DebeRetornar200YListaVacia() throws Exception {
        when(servicioTecnico.listarTickets(any())).thenReturn(Collections.emptyList());

        mockMvc.perform(get("/api/tecnico/tickets"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(0));
    }

    @Test
    public void aprobarTicket_DebeRetornar200ConMensaje() throws Exception {
        when(servicioTecnico.aprobarTicket(1001))
                .thenReturn(new TecnicoDTO.OperacionResponse("Ticket aprobado correctamente"));

        mockMvc.perform(put("/api/tecnico/tickets/1001/aprobar"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mensaje").value("Ticket aprobado correctamente"));
    }

    @Test
    public void rechazarTicket_DebeRetornar200ConMensaje() throws Exception {
        when(servicioTecnico.rechazarTicket(1001))
                .thenReturn(new TecnicoDTO.OperacionResponse("Ticket rechazado correctamente"));

        mockMvc.perform(put("/api/tecnico/tickets/1001/rechazar"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mensaje").value("Ticket rechazado correctamente"));
    }

    // ═══════════════════════════════════════════════════
    //  INCIDENCIAS
    // ═══════════════════════════════════════════════════

    @Test
    public void listarIncidencias_DebeRetornar200YListaVacia() throws Exception {
        when(servicioTecnico.listarIncidencias(any())).thenReturn(Collections.emptyList());

        mockMvc.perform(get("/api/tecnico/incidencias"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }

    @Test
    public void asignarIncidencia_DebeRetornar200ConMensaje() throws Exception {
        TecnicoDTO.AsignarRequest req = new TecnicoDTO.AsignarRequest();
        req.setDerivacion("Area de Tecnologia");

        when(servicioTecnico.asignarIncidencia(eq(1L), any(TecnicoDTO.AsignarRequest.class)))
                .thenReturn(new TecnicoDTO.OperacionResponse("Incidencia asignada correctamente"));

        mockMvc.perform(put("/api/tecnico/incidencias/1/asignar")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mensaje").value("Incidencia asignada correctamente"));
    }

    @Test
    public void rechazarIncidencia_DebeRetornar200ConMensaje() throws Exception {
        when(servicioTecnico.rechazarIncidencia(1L))
                .thenReturn(new TecnicoDTO.OperacionResponse("Incidencia rechazada correctamente"));

        mockMvc.perform(put("/api/tecnico/incidencias/1/rechazar"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mensaje").value("Incidencia rechazada correctamente"));
    }
}

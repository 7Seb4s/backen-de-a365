package com.backdea365.app.service;

import com.backdea365.app.dto.TecnicoDTO;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.server.ResponseStatusException;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;

// Pruebas unitarias para ServicioTecnico (rol GERENTE)
// Cubre: listar tickets/incidencias, aprobar, rechazar, asignar, derivar
@ExtendWith(MockitoExtension.class)
public class ServicioTecnicoTest {

    @Mock
    private JdbcTemplate jdbc;

    @InjectMocks
    private ServicioTecnico servicioTecnico;

    // ═══════════════════════════════════════════════════
    //  TICKETS
    // ═══════════════════════════════════════════════════

    @Test
    public void listarTickets_DebeRetornarListaVacia_CuandoNoHayTickets() {
        // Arrange
        Mockito.when(jdbc.query(eq("CALL sp_tecnico_tickets_listar(?)"),
                any(RowMapper.class), anyString()))
                .thenReturn(Collections.emptyList());

        // Act
        List<TecnicoDTO.TicketItem> resultado = servicioTecnico.listarTickets("");

        // Assert
        assertThat(resultado).isEmpty();
    }

    @Test
    public void aprobarTicket_DebeRetornarMensajeExitoso_CuandoTicketExiste() {
        // Arrange
        Mockito.when(jdbc.update(eq("CALL sp_tecnico_ticket_aprobar(?)"), eq(1001)))
                .thenReturn(1);

        // Act
        TecnicoDTO.OperacionResponse resultado = servicioTecnico.aprobarTicket(1001);

        // Assert
        assertThat(resultado.getMensaje()).contains("aprobado");
    }

    @Test
    public void aprobarTicket_DebeLanzar404_CuandoTicketNoExiste() {
        // Arrange
        Mockito.when(jdbc.update(eq("CALL sp_tecnico_ticket_aprobar(?)"), eq(9999)))
                .thenReturn(0);

        // Act & Assert
        assertThatThrownBy(() -> servicioTecnico.aprobarTicket(9999))
                .isInstanceOf(ResponseStatusException.class)
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    public void rechazarTicket_DebeRetornarMensajeExitoso_CuandoTicketExiste() {
        // Arrange
        Mockito.when(jdbc.update(eq("CALL sp_tecnico_ticket_rechazar(?)"), eq(1001)))
                .thenReturn(1);

        // Act
        TecnicoDTO.OperacionResponse resultado = servicioTecnico.rechazarTicket(1001);

        // Assert
        assertThat(resultado.getMensaje()).contains("rechazado");
    }

    @Test
    public void rechazarTicket_DebeLanzar404_CuandoTicketNoExiste() {
        // Arrange
        Mockito.when(jdbc.update(eq("CALL sp_tecnico_ticket_rechazar(?)"), eq(9999)))
                .thenReturn(0);

        // Act & Assert
        assertThatThrownBy(() -> servicioTecnico.rechazarTicket(9999))
                .isInstanceOf(ResponseStatusException.class)
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
    }

    // ═══════════════════════════════════════════════════
    //  INCIDENCIAS
    // ═══════════════════════════════════════════════════

    @Test
    public void listarIncidencias_DebeRetornarListaVacia_CuandoNoHayIncidencias() {
        // Arrange
        Mockito.when(jdbc.query(eq("CALL sp_tecnico_incidencias_listar(?)"),
                any(RowMapper.class), anyString()))
                .thenReturn(Collections.emptyList());

        // Act
        List<TecnicoDTO.IncidenciaItem> resultado = servicioTecnico.listarIncidencias("");

        // Assert
        assertThat(resultado).isEmpty();
    }

    @Test
    public void asignarIncidencia_DebeLanzarBadRequest_CuandoDerivacionEsVacia() {
        // Arrange
        TecnicoDTO.AsignarRequest req = new TecnicoDTO.AsignarRequest();
        req.setDerivacion("   ");

        // Act & Assert
        assertThatThrownBy(() -> servicioTecnico.asignarIncidencia(1L, req))
                .isInstanceOf(ResponseStatusException.class)
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);

        Mockito.verifyNoInteractions(jdbc);
    }

    @Test
    public void asignarIncidencia_DebeRetornarExitoso_CuandoDatosCorrectos() {
        // Arrange
        TecnicoDTO.AsignarRequest req = new TecnicoDTO.AsignarRequest();
        req.setDerivacion("Area de Tecnologia");

        Mockito.when(jdbc.update(eq("CALL sp_tecnico_incidencia_asignar(?, ?)"),
                eq(1L), eq("Area de Tecnologia")))
                .thenReturn(1);

        // Act
        TecnicoDTO.OperacionResponse resultado = servicioTecnico.asignarIncidencia(1L, req);

        // Assert
        assertThat(resultado.getMensaje()).contains("asignada");
    }

    @Test
    public void rechazarIncidencia_DebeRetornarExitoso_CuandoExiste() {
        // Arrange
        Mockito.when(jdbc.update(eq("CALL sp_tecnico_incidencia_rechazar(?)"), eq(1L)))
                .thenReturn(1);

        // Act
        TecnicoDTO.OperacionResponse resultado = servicioTecnico.rechazarIncidencia(1L);

        // Assert
        assertThat(resultado.getMensaje()).contains("rechazada");
    }

    @Test
    public void rechazarIncidencia_DebeLanzar404_CuandoNoExiste() {
        // Arrange
        Mockito.when(jdbc.update(eq("CALL sp_tecnico_incidencia_rechazar(?)"), eq(999L)))
                .thenReturn(0);

        // Act & Assert
        assertThatThrownBy(() -> servicioTecnico.rechazarIncidencia(999L))
                .isInstanceOf(ResponseStatusException.class)
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
    }
}

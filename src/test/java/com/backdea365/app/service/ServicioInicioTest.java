package com.backdea365.app.service;

import com.backdena365.app.dto.InicioDTO;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;

@ExtendWith(MockitoExtension.class)
public class ServicioInicioTest {

    @Mock
    private JdbcTemplate jdbc;

    @InjectMocks
    private ServicioInicio servicioInicio;

    // ═══════════════════════════════════════════════════
    //  1. PRUEBAS PARA OBTENER RESUMEN
    // ═══════════════════════════════════════════════════

    @Test
    public void obtenerResumen_DebeRetornarDatosDeBD_CuandoUsuarioTieneTickets() {
        // Arrange
        Integer idUsuario = 5;
        InicioDTO.ResumenTickets resumenMock = new InicioDTO.ResumenTickets(3, 12, 1);

        Mockito.when(jdbc.queryForObject(
                eq("CALL sp_inicio_resumen_tickets(?)"),
                any(RowMapper.class),
                eq(idUsuario)
        )).thenReturn(resumenMock);

        // Act
        InicioDTO.ResumenTickets resultado = servicioInicio.obtenerResumen(idUsuario);

        // Assert
        assertThat(resultado).isNotNull();
        assertThat(resultado.getTicketsPendientes()).isEqualTo(3);
        assertThat(resultado.getTicketsAtendidos()).isEqualTo(12);
        assertThat(resultado.getTicketsCancelados()).isEqualTo(1);
    }

    @Test
    public void obtenerResumen_DebeRetornarCeros_CuandoLaBDExcepciona() {
        // Arrange
        Integer idUsuario = 99;

        // Simulamos que la BD lanza un error (ej. usuario no encontrado o timeout)
        Mockito.when(jdbc.queryForObject(anyString(), any(RowMapper.class), eq(idUsuario)))
                .thenThrow(new org.springframework.dao.EmptyResultDataAccessException(1));

        // Act
        InicioDTO.ResumenTickets resultado = servicioInicio.obtenerResumen(idUsuario);

        // Assert
        // El bloque try-catch debe capturar el error y devolver la estructura limpia en 0
        assertThat(resultado).isNotNull();
        assertThat(resultado.getTicketsPendientes()).isEqualTo(0);
        assertThat(resultado.getTicketsAtendidos()).isEqualTo(0);
        assertThat(resultado.getTicketsCancelados()).isEqualTo(0);
    }

    // ═══════════════════════════════════════════════════
    //  2. PRUEBAS PARA OBTENER TICKET ACTIVO
    // ═══════════════════════════════════════════════════

    @Test
    public void obtenerTicketActivo_DebeRetornarPrimerTicket_CuandoLaListaNoEstaVacia() {
        // Arrange
        Integer idUsuario = 5;
        InicioDTO.TicketActivo ticketMock = new InicioDTO.TicketActivo(
                100L, 202601, "SOPORTE", "ALTA", "EN_PROCESO", "EMP001"
        );

        Mockito.when(jdbc.query(
                eq("CALL sp_inicio_ticket_activo(?)"),
                any(RowMapper.class),
                eq(idUsuario)
        )).thenReturn(List.of(ticketMock));

        // Act
        InicioDTO.TicketActivo resultado = servicioInicio.obtenerTicketActivo(idUsuario);

        // Assert
        assertThat(resultado).isNotNull();
        assertThat(resultado.getIdTicket()).isEqualTo(100L);
        assertThat(resultado.getNumeroTicket()).isEqualTo(202601);
        assertThat(resultado.getPrioridad()).isEqualTo("ALTA");
    }

    @Test
    public void obtenerTicketActivo_DebeRetornarNull_CuandoLaListaEstaVacia() {
        // Arrange
        Integer idUsuario = 5;

        // Simulamos que el SP no encuentra ningún ticket activo/pendiente
        Mockito.when(jdbc.query(anyString(), any(RowMapper.class), eq(idUsuario)))
                .thenReturn(Collections.emptyList());

        // Act
        InicioDTO.TicketActivo resultado = servicioInicio.obtenerTicketActivo(idUsuario);

        // Assert
        assertThat(resultado).isNull();
    }

    // ═══════════════════════════════════════════════════
    //  3. PRUEBAS PARA OBTENER ACTIVIDAD
    // ═══════════════════════════════════════════════════

    @Test
    public void obtenerActividad_DebeRetornarListaDeAcciones_CuandoIdTicketEsValido() {
        // Arrange
        Long idTicket = 100L;
        InicioDTO.ActividadItem item1 = new InicioDTO.ActividadItem("Asignación de analista", "2026-06-08T10:15:30");
        InicioDTO.ActividadItem item2 = new InicioDTO.ActividadItem("Cambio de estado a EN PROCESO", "2026-06-08T11:00:00");

        Mockito.when(jdbc.query(
                eq("CALL sp_inicio_actividad_ticket(?)"),
                any(RowMapper.class),
                eq(idTicket)
        )).thenReturn(List.of(item1, item2));

        // Act
        List<InicioDTO.ActividadItem> resultado = servicioInicio.obtenerActividad(idTicket);

        // Assert
        assertThat(resultado).isNotEmpty().hasSize(2);
        assertThat(resultado.get(0).getDescripcion()).isEqualTo("Asignación de analista");
        assertThat(resultado.get(1).getCreadoEn()).isEqualTo("2026-06-08T11:00:00");
    }

    // ═══════════════════════════════════════════════════
    //  4. PRUEBAS PARA OBTENER CALENDARIO
    // ═══════════════════════════════════════════════════

    @Test
    public void obtenerCalendario_DebeRetornarDiasConTickets_CuandoSeConsultaMesYAnio() {
        // Arrange
        Integer idUsuario = 5;
        Integer anio = 2026;
        Integer mes = 6;

        InicioDTO.CalendarioDia dia1 = new InicioDTO.CalendarioDia("2026-06-01", 2);
        InicioDTO.CalendarioDia dia2 = new InicioDTO.CalendarioDia("2026-06-08", 5);

        Mockito.when(jdbc.query(
                eq("CALL sp_inicio_calendario_tickets_mes(?, ?, ?)"),
                any(RowMapper.class),
                eq(idUsuario),
                eq(anio),
                eq(mes)
        )).thenReturn(List.of(dia1, dia2));

        // Act
        List<InicioDTO.CalendarioDia> resultado = servicioInicio.obtenerCalendario(idUsuario, anio, mes);

        // Assert
        assertThat(resultado).isNotEmpty().hasSize(2);
        assertThat(resultado.get(0).getDia()).isEqualTo("2026-06-01");
        assertThat(resultado.get(0).getCantidad()).isEqualTo(2);
        assertThat(resultado.get(1).getDia()).isEqualTo("2026-06-08");
        assertThat(resultado.get(1).getCantidad()).isEqualTo(5);
    }
}
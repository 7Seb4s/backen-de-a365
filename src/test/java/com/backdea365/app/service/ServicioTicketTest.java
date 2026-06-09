package com.backdea365.app.service;

import com.backdea365.app.dto.TicketDTO;
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

import java.sql.Time;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;

@ExtendWith(MockitoExtension.class)
public class ServicioTicketTest {

    @Mock
    private JdbcTemplate jdbc;

    @InjectMocks
    private ServicioTicket servicioTicket;

    // ═══════════════════════════════════════════════════
    //  1. PRUEBAS PARA EL MÉTODO LISTAR POR TAB
    // ═══════════════════════════════════════════════════

    @Test
    public void listarPorTab_DebeRetornarTickets_CuandoTabEsValido() {
        // Arrange
        Integer idUsuario = 7;
        String tab = "pendientes"; // Debe mapearse internamente a "PENDIENTES"

        TicketDTO.ItemResumen ticketMock = new TicketDTO.ItemResumen(101, "En proceso", "Área de Sistemas", false);

        Mockito.when(jdbc.query(
                eq("CALL sp_tickets_listar(?, ?)"),
                any(RowMapper.class),
                eq(idUsuario),
                eq("PENDIENTES")
        )).thenReturn(List.of(ticketMock));

        // Act
        List<TicketDTO.ItemResumen> resultado = servicioTicket.listarPorTab(tab, idUsuario);

        // Assert
        assertThat(resultado).isNotEmpty().hasSize(1);
        assertThat(resultado.get(0).getNumero()).isEqualTo(101);
        assertThat(resultado.get(0).getEstado()).isEqualTo("En proceso");
    }

    @Test
    public void listarPorTab_DebeLanzarBadRequest_CuandoTabNoEsSoportado() {
        // Arrange
        Integer idUsuario = 7;
        String tabInvalido = "archivados_antiguos";

        // Act & Assert
        assertThatThrownBy(() -> servicioTicket.listarPorTab(tabInvalido, idUsuario))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("Tab invalido")
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);

        Mockito.verify(jdbc, Mockito.never()).query(anyString(), any(RowMapper.class), any(), any());
    }

    // ═══════════════════════════════════════════════════
    //  2. PRUEBAS PARA EL MÉTODO OBTENER DETALLE
    // ═══════════════════════════════════════════════════

    @Test
    public void obtenerDetalle_DebeLanzarNotFound_CuandoElTicketNoExisteEnBD() {
        // Arrange
        Integer numeroTicket = 9999;

        // Simulamos que el procedimiento almacenado sp_ticket_mas_info falla o no encuentra filas
        Mockito.when(jdbc.queryForMap(eq("CALL sp_ticket_mas_info(?)"), eq(numeroTicket)))
                .thenThrow(new org.springframework.dao.EmptyResultDataAccessException(1));

        // Act & Assert
        assertThatThrownBy(() -> servicioTicket.obtenerDetalle(numeroTicket))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("Ticket no encontrado")
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    public void obtenerDetalle_DebeMapearCamposYEstadisticas_CuandoTicketExiste() {
        // Arrange
        Integer numeroTicket = 2026;
        Integer idSolicitante = 14;

        // Construcción de la fila mock que retorna el SP sp_ticket_mas_info
        Map<String, Object> filaMock = new HashMap<>();
        filaMock.put("nombre_completo", "Erik Smit Ventura");
        filaMock.put("pais", "Perú");
        filaMock.put("tiempo_respuesta", Time.valueOf("00:12:30")); // <= 15 min -> Rápido
        filaMock.put("tiempo_total", Time.valueOf("02:15:00"));
        filaMock.put("telefono", "987654321");
        filaMock.put("correo", "erik@mail.com");
        filaMock.put("plataforma", "WEB");
        filaMock.put("numero_ticket", numeroTicket);
        filaMock.put("tipo_ticket", "SOPORTE");
        filaMock.put("prioridad", "ALTA");
        filaMock.put("codigo_asignado", "AG_99");

        Mockito.when(jdbc.queryForMap(eq("CALL sp_ticket_mas_info(?)"), eq(numeroTicket)))
                .thenReturn(filaMock);

        // Mocks para las tres consultas internas adicionales sobre estadísticas del solicitante
        Mockito.when(jdbc.queryForObject(eq("SELECT id_solicitante FROM tickets WHERE numero_ticket = ?"), eq(Integer.class), eq(numeroTicket)))
                .thenReturn(idSolicitante);
        Mockito.when(jdbc.queryForObject(eq("SELECT COUNT(*) FROM tickets WHERE id_solicitante = ?"), eq(Integer.class), eq(idSolicitante)))
                .thenReturn(15); // Total histórico
        Mockito.when(jdbc.queryForObject(eq("SELECT COUNT(*) FROM tickets WHERE id_solicitante = ? AND estado = 'PENDIENTE'"), eq(Integer.class), eq(idSolicitante)))
                .thenReturn(4);  // Total pendientes

        // Act
        TicketDTO.DetalleResponse resultado = servicioTicket.obtenerDetalle(numeroTicket);

        // Assert
        assertThat(resultado).isNotNull();
        assertThat(resultado.getUsuarioNombre()).isEqualTo("Erik Smit Ventura");
        assertThat(resultado.getTickets()).isEqualTo(15);
        assertThat(resultado.getTicketsPendientes()).isEqualTo(4);
        assertThat(resultado.getVelocidadRespuesta()).isEqualTo("Rapido"); // Verifica lógica de clasificación de velocidad
        assertThat(resultado.getTicketActivoId()).isEqualTo("#2026");
        assertThat(resultado.getAsignadoA()).isEqualTo("AG_99");
    }

    // ═══════════════════════════════════════════════════
    //  3. PRUEBAS PARA EL MÉTODO CREAR TICKET
    // ═══════════════════════════════════════════════════

    @Test
    public void crear_DebeEjecutarSpYRetornarUltimoTicketCreado() {
        // Arrange
        Integer idUsuario = 7;
        TicketDTO.CrearRequest request = new TicketDTO.CrearRequest(
                "Fallo de Red", "Planta A", "No conecta con el servidor principal", "ALTA"
        );

        TicketDTO.ItemResumen itemEsperado = new TicketDTO.ItemResumen(5001, "Pendiente", "Planta A", false);

        // Simulamos la consulta SELECT que busca el último registro persistido
        Mockito.when(jdbc.queryForObject(
                eq("SELECT numero_ticket, subestado, locacion_area FROM tickets WHERE id_solicitante = ? ORDER BY numero_ticket DESC LIMIT 1"),
                any(RowMapper.class),
                eq(idUsuario)
        )).thenReturn(itemEsperado);

        // Act
        TicketDTO.ItemResumen resultado = servicioTicket.crear(request, idUsuario);

        // Assert
        assertThat(resultado).isNotNull();
        assertThat(resultado.getNumero()).isEqualTo(5001);
        assertThat(resultado.getLocacion()).isEqualTo("Planta A");

        // Verificamos que se haya invocado la creación estructurada por SP
        Mockito.verify(jdbc, Mockito.times(1)).update(
                eq("CALL sp_ticket_crear(?, ?, ?, ?, ?)"),
                eq(idUsuario),
                eq("Fallo de Red"),
                eq("Planta A"),
                eq("No conecta con el servidor principal"),
                eq("ALTA")
        );
    }
}
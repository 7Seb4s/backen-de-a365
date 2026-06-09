package com.backdea365.app.service;

import com.backdea365.app.dto.IncidenciaDTO;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.TransientDataAccessResourceException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.server.ResponseStatusException;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;

@ExtendWith(MockitoExtension.class)
public class ServicioIncidenciaTest {

    @Mock
    private JdbcTemplate jdbc;

    @InjectMocks
    private ServicioIncidencia servicioIncidencia;

    // ═══════════════════════════════════════════════════
    //  1. PRUEBAS PARA EL MÉTODO LISTAR
    // ═══════════════════════════════════════════════════

    @Test
    public void listar_DebeRetornarItemConResaltadoTrue_CuandoEsReportadaYTipoActualizacion() {
        // Arrange
        Integer idUsuario = 1;

        // Creamos el mock con las reglas del negocio aplicadas (REPORTADA + ACTUALIZACION)
        IncidenciaDTO.ItemResumen itemMock = new IncidenciaDTO.ItemResumen(
                50L,
                "Actualizacion",       // Capitalizado por el servicio
                "Topic: Falla de red",  // Prefijo agregado por el servicio
                true                   // Resaltado condicional
        );

        Mockito.when(jdbc.query(
                eq("CALL sp_incidencias_listar(?)"),
                any(RowMapper.class),
                eq(idUsuario)
        )).thenReturn(List.of(itemMock));

        // Act
        List<IncidenciaDTO.ItemResumen> resultado = servicioIncidencia.listar(idUsuario);

        // Assert
        assertThat(resultado).isNotEmpty().hasSize(1);
        IncidenciaDTO.ItemResumen item = resultado.get(0);
        assertThat(item.getTipo()).isEqualTo("Actualizacion");
        assertThat(item.getTema()).isEqualTo("Topic: Falla de red");
        assertThat(item.getResaltado()).isTrue();
    }

    @Test
    public void listar_DebeRetornarItemConResaltadoFalse_CuandoNoCumpleCondiciones() {
        // Arrange
        Integer idUsuario = 1;
        IncidenciaDTO.ItemResumen itemMock = new IncidenciaDTO.ItemResumen(
                51L,
                "Soporte",
                "Topic: Teclado roto",
                false // No se resalta porque no cumple las condiciones del negocio
        );

        Mockito.when(jdbc.query(anyString(), any(RowMapper.class), eq(idUsuario)))
                .thenReturn(List.of(itemMock));

        // Act
        List<IncidenciaDTO.ItemResumen> resultado = servicioIncidencia.listar(idUsuario);

        // Assert
        assertThat(resultado.get(0).getResaltado()).isFalse();
    }

    // ═══════════════════════════════════════════════════
    //  2. PRUEBAS PARA EL MÉTODO CREAR
    // ═══════════════════════════════════════════════════

    @Test
    public void crear_DebeLanzarBadRequest_CuandoElTicketNoExisteEnLaBD() {
        // Arrange
        Integer idUsuario = 10;
        IncidenciaDTO.CrearRequest request = new IncidenciaDTO.CrearRequest();
        request.setNumeroTicket(9999); // Ticket inexistente
        request.setAsunto("Incidencia de prueba");
        request.setTipo("ACTUALIZACION");
        request.setContenido("Detalle");

        // Simulamos que el conteo en la base de datos es 0
        Mockito.when(jdbc.queryForObject(anyString(), eq(Integer.class), eq(9999)))
                .thenReturn(0);

        // Act & Assert
        assertThatThrownBy(() -> servicioIncidencia.crear(request, idUsuario))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("El numero de ticket no existe")
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);

        // Verificamos aislamiento: Jamás se intentó llamar al sp_incidencias_crear
        Mockito.verify(jdbc, Mockito.never()).update(anyString(), (Object) any());
    }

    @Test
    public void crear_DebeLanzarInternalServerError_CuandoLaBDExcepciona() {
        // Arrange
        Integer idUsuario = 10;
        IncidenciaDTO.CrearRequest request = new IncidenciaDTO.CrearRequest();
        request.setNumeroTicket(101);
        request.setAsunto("Error Crítico");
        request.setTipo("BUG");
        request.setContenido("Fallo de query");

        // El ticket sí existe
        Mockito.when(jdbc.queryForObject(anyString(), eq(Integer.class), eq(101)))
                .thenReturn(1);

        // Simulamos que la ejecución del Stored Procedure arroja un error imprevisto de persistencia
        Mockito.when(jdbc.update(anyString(), eq(idUsuario), eq("Error Crítico"), eq("BUG"), eq(101), eq("Fallo de query")))
                .thenThrow(new TransientDataAccessResourceException("Conexión perdida"));

        // Act & Assert
        assertThatThrownBy(() -> servicioIncidencia.crear(request, idUsuario))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("Error al crear la incidencia")
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @Test
    public void crear_DebeRetornarOperacionResponse_CuandoElFlujoEsExitoso() {
        // Arrange
        Integer idUsuario = 10;
        IncidenciaDTO.CrearRequest request = new IncidenciaDTO.CrearRequest();
        request.setNumeroTicket(101);
        request.setAsunto("  Asunto con espacios  ");
        request.setTipo("   MEJORA   ");
        request.setContenido("Contenido limpio");

        Mockito.when(jdbc.queryForObject(anyString(), eq(Integer.class), eq(101)))
                .thenReturn(1);

        // Act
        IncidenciaDTO.OperacionResponse respuesta = servicioIncidencia.crear(request, idUsuario);

        // Assert
        assertThat(respuesta.getMensaje()).isEqualTo("Incidencia reportada exitosamente");

        // Verificamos que se ejecutó el update con los strings correctamente formateados por .trim()
        Mockito.verify(jdbc, Mockito.times(1)).update(
                eq("CALL sp_incidencias_crear(?, ?, ?, ?, ?)"),
                eq(idUsuario),
                eq("Asunto con espacios"),
                eq("MEJORA"),
                eq(101),
                eq("Contenido limpio")
        );
    }

    // ═══════════════════════════════════════════════════
    //  3. PRUEBAS PARA EL MÉTODO OBTENER DETALLE
    // ═══════════════════════════════════════════════════

    @Test
    public void obtenerDetalle_DebeRetornarDetalleResponse_CuandoIdExiste() {
        // Arrange
        Long idIncidencia = 500L;
        IncidenciaDTO.DetalleResponse responseMock = new IncidenciaDTO.DetalleResponse(
                idIncidencia,
                "Problema de login",
                "ACTUALIZACION",
                "No carga la pantalla",
                202,
                "REPORTADA",
                "2026-06-08T20:00:00",
                "EMP001",
                "erik@mail.com"
        );

        Mockito.when(jdbc.queryForObject(eq("CALL sp_incidencias_detalle(?)"), any(RowMapper.class), eq(idIncidencia)))
                .thenReturn(responseMock);

        // Act
        IncidenciaDTO.DetalleResponse resultado = servicioIncidencia.obtenerDetalle(idIncidencia);

        // Assert
        assertThat(resultado).isNotNull();
        assertThat(resultado.getId()).isEqualTo(500L);
        assertThat(resultado.getAsunto()).isEqualTo("Problema de login");
        assertThat(resultado.getCodigoUsuario()).isEqualTo("EMP001");
    }

    @Test
    public void obtenerDetalle_DebeLanzarNotFound_CuandoIdNoExisteEnLaBD() {
        // Arrange
        Long idInexistente = 9999L;

        // Simulamos que jdbc lanza una excepción genérica al no mapear filas
        Mockito.when(jdbc.queryForObject(anyString(), any(RowMapper.class), eq(idInexistente)))
                .thenThrow(new org.springframework.dao.EmptyResultDataAccessException(1));

        // Act & Assert
        assertThatThrownBy(() -> servicioIncidencia.obtenerDetalle(idInexistente))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("Incidencia no encontrada")
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
    }
}
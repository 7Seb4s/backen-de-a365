package com.backdea365.app.service;

import com.backdena365.app.dto.AdminDTO;
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;

@ExtendWith(MockitoExtension.class)
public class ServicioAdminTest {

    @Mock
    private JdbcTemplate jdbc;

    @InjectMocks
    private ServicioAdmin servicioAdmin;

    // ═══════════════════════════════════════════════════
    //  1. PRUEBAS DE VALIDACIONES Y EXCEPCIONES (400 / 404)
    // ═══════════════════════════════════════════════════

    @Test
    public void moverTicket_DebeLanzarBadRequest_CuandoColumnaEsInvalida() {
        // Arrange
        Integer numeroTicket = 105;
        AdminDTO.MoverTicketRequest requestInvalido = new AdminDTO.MoverTicketRequest();
        requestInvalido.setColumna("COLUMNA_INVENTADA"); // No válida

        // Act & Assert
        assertThatThrownBy(() -> servicioAdmin.moverTicket(numeroTicket, requestInvalido))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("Columna inválida")
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);

        // Verifica que no se interactuó con la base de datos debido al error previo
        Mockito.verifyNoInteractions(jdbc);
    }

    @Test
    public void cambiarRol_DebeLanzarBadRequest_CuandoRolNoExisteEnEnum() {
        // Arrange
        Integer idUsuario = 1;
        AdminDTO.CambiarRolRequest requestInvalido = new AdminDTO.CambiarRolRequest();
        requestInvalido.setRol("SUPER_USER"); // No es EMPLEADO, ADMINISTRADOR ni GERENTE

        // Act & Assert
        assertThatThrownBy(() -> servicioAdmin.cambiarRol(idUsuario, requestInvalido))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("Rol inválido")
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);

        Mockito.verifyNoInteractions(jdbc);
    }

    @Test
    public void enviarMensaje_DebeLanzarBadRequest_CuandoContenidoEsBlanco() {
        // Arrange
        Integer numeroTicket = 200;
        Integer idRemitente = 5;
        AdminDTO.EnviarMensajeRequest requestVacio = new AdminDTO.EnviarMensajeRequest();
        requestVacio.setContenido("   "); // Vacío con espacios

        // Act & Assert
        assertThatThrownBy(() -> servicioAdmin.enviarMensaje(numeroTicket, idRemitente, requestVacio))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("El contenido del mensaje no puede estar vacío");

        Mockito.verifyNoInteractions(jdbc);
    }

    @Test
    public void obtenerModalTicket_DebeLanzarNotFound_CuandoListaEstaVacia() {
        // Arrange
        Integer numeroTicket = 999;
        // Simulamos que el procedimiento almacenado devuelve una lista vacía
        Mockito.when(jdbc.query(anyString(), any(RowMapper.class), eq(numeroTicket)))
                .thenReturn(Collections.emptyList());

        // Act & Assert
        assertThatThrownBy(() -> servicioAdmin.obtenerModalTicket(numeroTicket))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("Ticket no encontrado")
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
    }

    // ═══════════════════════════════════════════════════
    //  2. PRUEBAS DE FLUJO CORRECTO Y ESCENARIOS DTO
    // ═══════════════════════════════════════════════════

    @Test
    public void moverTicket_DebeEjecutarCorrectamente_CuandoColumnaEsValida() {
        // Arrange
        Integer numeroTicket = 101;
        AdminDTO.MoverTicketRequest requestValido = new AdminDTO.MoverTicketRequest();
        requestValido.setColumna("en_revision "); // Con minúsculas y espacios para probar el formateo

        // Act
        AdminDTO.OperacionResponse respuesta = servicioAdmin.moverTicket(numeroTicket, requestValido);

        // Assert
        assertThat(respuesta.getMensaje()).isEqualTo("Ticket movido correctamente");

        // Verifica que se llamó al SP limpiando el texto a "EN_REVISION"
        Mockito.verify(jdbc, Mockito.times(1))
                .update("CALL sp_admin_ticket_mover(?, ?)", numeroTicket, "EN_REVISION");
    }

    @Test
    public void obtenerColumnaTablero_DebeRetornarListaDeItems_CuandoExistanTickets() {
        // Arrange
        String columna = "EN_REVISION";
        String textoBusqueda = "error login";

        AdminDTO.TableroTicketItem itemMock = new AdminDTO.TableroTicketItem(
                1001,
                "Error en Login con Google",
                "2026-06-08T19:30:00",
                "EN_REVISION",
                "ASIGNADO",
                "El usuario no puede ingresar"
        );
        List<AdminDTO.TableroTicketItem> listaMock = List.of(itemMock);

        Mockito.when(jdbc.query(
                eq("CALL sp_admin_tablero_tickets(?, ?)"),
                any(RowMapper.class),
                eq(columna),
                eq("error login")
        )).thenReturn(listaMock);

        // Act
        List<AdminDTO.TableroTicketItem> resultado = servicioAdmin.obtenerColumnaTablero(columna, textoBusqueda);

        // Assert
        assertThat(resultado).isNotEmpty();
        assertThat(resultado).hasSize(1);
        assertThat(resultado.get(0).getNumeroTicket()).isEqualTo(1001);
        assertThat(resultado.get(0).getAsunto()).isEqualTo("Error en Login con Google");
    }

    @Test
    public void obtenerResumenTicketsMes_DebeRetornarTotales_CuandoLaBDEntregaDatos() {
        // Arrange
        Integer anio = 2026;
        Integer mes = 6;

        AdminDTO.ResumenTicketsMes resumenMock = new AdminDTO.ResumenTicketsMes(
                5, 2, 13, 20, 25, 10, 65
        );

        Mockito.when(jdbc.query(
                eq("CALL sp_admin_gestion_tickets_mes(?, ?)"),
                any(RowMapper.class),
                eq(anio),
                eq(mes)
        )).thenReturn(List.of(resumenMock));

        // Act
        AdminDTO.ResumenTicketsMes resultado = servicioAdmin.obtenerResumenTicketsMes(anio, mes);

        // Assert
        assertThat(resultado).isNotNull();
        assertThat(resultado.getTotal()).isEqualTo(20);
        assertThat(resultado.getAtendidos()).isEqualTo(13);
        assertThat(resultado.getPctAtendidos()).isEqualTo(65);
    }

    @Test
    public void obtenerResumenTicketsMes_DebeRetornarObjetoEnCero_CuandoLaBDNoTieneRegistros() {
        // Arrange
        Integer anio = 2026;
        Integer mes = 12;

        Mockito.when(jdbc.query(
                eq("CALL sp_admin_gestion_tickets_mes(?, ?)"),
                any(RowMapper.class),
                eq(anio),
                eq(mes)
        )).thenReturn(Collections.emptyList());

        // Act
        AdminDTO.ResumenTicketsMes resultado = servicioAdmin.obtenerResumenTicketsMes(anio, mes);

        // Assert
        assertThat(resultado).isNotNull();
        assertThat(resultado.getTotal()).isEqualTo(0);
        assertThat(resultado.getPendientes()).isEqualTo(0);
        assertThat(resultado.getPctAtendidos()).isEqualTo(0);
    }
}
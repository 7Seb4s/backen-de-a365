package com.backdea365.app.service;

import com.backdena365.app.dto.UsuarioDTO;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementCreator;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;

@ExtendWith(MockitoExtension.class)
public class ServicioUsuarioTest {

    @Mock
    private JdbcTemplate jdbc;

    @Mock
    private PasswordEncoder encoder;

    @InjectMocks
    private ServicioUsuario servicioUsuario;

    // ═══════════════════════════════════════════════════
    //  1. PRUEBAS PARA EL MÉTODO CREAR USUARIO
    // ═══════════════════════════════════════════════════

    @Test
    public void crearUsuario_DebeLanzarBadRequest_CuandoRolEsInvalido() {
        // Arrange
        UsuarioDTO.CrearRequest request = new UsuarioDTO.CrearRequest();
        request.setRol("SUPER_USUARIO"); // Rol fuera del switch permitido

        // Act & Assert
        assertThatThrownBy(() -> servicioUsuario.crearUsuario(request))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("Rol inválido")
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);

        Mockito.verify(jdbc, Mockito.never()).queryForObject(anyString(), eq(Integer.class), any());
    }

    @Test
    public void crearUsuario_DebeLanzarConflict_CuandoCorreoYaEstaRegistrado() {
        // Arrange
        UsuarioDTO.CrearRequest request = new UsuarioDTO.CrearRequest();
        request.setRol("EMPLEADO");
        request.setCorreo("duplicado@mail.com");

        // Simulamos que la consulta de conteo encuentra un correo existente
        Mockito.when(jdbc.queryForObject(
                eq("SELECT COUNT(*) FROM usuarios_login WHERE correo = ?"),
                eq(Integer.class),
                eq("duplicado@mail.com")
        )).thenReturn(1);

        // Act & Assert
        assertThatThrownBy(() -> servicioUsuario.crearUsuario(request))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("El correo ya está registrado")
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.CONFLICT);

        // Verificamos que el flujo se detiene y no avanza a validar el DNI
        Mockito.verify(jdbc, Mockito.never()).queryForObject(contains("usuario_detail"), eq(Integer.class), any());
    }

    @Test
    public void crearUsuario_DebeLanzarConflict_CuandoDniYaEstaRegistrado() {
        // Arrange
        UsuarioDTO.CrearRequest request = new UsuarioDTO.CrearRequest();
        request.setRol("ADMINISTRADOR");
        request.setCorreo("valido@mail.com");
        request.setDni("77778888");

        // El correo no está registrado (0), pero el DNI sí (1)
        Mockito.when(jdbc.queryForObject(eq("SELECT COUNT(*) FROM usuarios_login WHERE correo = ?"), eq(Integer.class), eq("valido@mail.com")))
                .thenReturn(0);
        Mockito.when(jdbc.queryForObject(eq("SELECT COUNT(*) FROM usuario_detalle WHERE dni = ?"), eq(Integer.class), eq("77778888")))
                .thenReturn(1);

        // Act & Assert
        assertThatThrownBy(() -> servicioUsuario.crearUsuario(request))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("El DNI ya está registrado")
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    public void crearUsuario_DebeLanzarInternalServerError_CuandoKeyHolderNoRetornaId() {
        // Arrange
        UsuarioDTO.CrearRequest request = new UsuarioDTO.CrearRequest();
        request.setRol("EMPLEADO");
        request.setCorreo("erik@mail.com");
        request.setDni("12345678");
        request.setNombreCompleto("Erik");
        request.setApellidoCompleto("Smit");
        request.setContrasena("Segura123!");

        Mockito.when(jdbc.queryForObject(anyString(), eq(Integer.class), any()))
                .thenReturn(0); // Pasa validaciones de correo, DNI y retorna 0 para el contador de códigos
        Mockito.when(encoder.encode(anyString())).thenReturn("hashedPass");

        // Simulamos que la base de datos no puede generar o devolver la PK primaria
        try (MockedConstruction<GeneratedKeyHolder> mockedKh = Mockito.mockConstruction(GeneratedKeyHolder.class,
                (mock, context) -> {
                    Mockito.when(mock.getKey()).thenReturn(null);
                })) {

            // Act & Assert
            assertThatThrownBy(() -> servicioUsuario.crearUsuario(request))
                    .isInstanceOf(ResponseStatusException.class)
                    .hasMessageContaining("Error al obtener ID del usuario")
                    .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                    .isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Test
    public void crearUsuario_DebeGuardarUsuarioYDetalles_CuandoTodaLaInformacionEsValida() {
        // Arrange
        UsuarioDTO.CrearRequest request = new UsuarioDTO.CrearRequest();
        request.setRol("GERENTE");
        request.setCorreo("gerencia@mail.com");
        request.setDni("99999999");
        request.setNombreCompleto("Erik Smit");
        request.setApellidoCompleto("Ventura Hernández");
        request.setContrasena("ClaveSecreta1!");
        request.setTelefono("999888777");

        // Mocks de conteos: correo libre (0), DNI libre (0), usuarios con rol GERENTE actuales (3) -> Siguiente será GER004
        Mockito.when(jdbc.queryForObject(eq("SELECT COUNT(*) FROM usuarios_login WHERE correo = ?"), eq(Integer.class), eq("gerencia@mail.com"))).thenReturn(0);
        Mockito.when(jdbc.queryForObject(eq("SELECT COUNT(*) FROM usuario_detalle WHERE dni = ?"), eq(Integer.class), eq("99999999"))).thenReturn(0);
        Mockito.when(jdbc.queryForObject(eq("SELECT COUNT(*) FROM usuarios_login WHERE rol = ?"), eq(Integer.class), eq("GERENTE"))).thenReturn(3);

        Mockito.when(encoder.encode("ClaveSecreta1!")).thenReturn("$2a$10$HashSeguroDeLombok");

        // Simulamos la inserción exitosa interceptando la instancia del KeyHolder
        try (MockedConstruction<GeneratedKeyHolder> mockedKh = Mockito.mockConstruction(GeneratedKeyHolder.class,
                (mock, context) -> {
                    Mockito.when(mock.getKey()).thenReturn(150); // Asigna ID generado ficticio 150
                })) {

            // Act
            UsuarioDTO.CrearResponse response = servicioUsuario.crearUsuario(request);

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getId()).isEqualTo(150);
            assertThat(response.getCodigo()).isEqualTo("GER004");
            assertThat(response.getNombreCompleto()).isEqualTo("Erik Smit Ventura Hernández");
            assertThat(response.getRol()).isEqualTo("GERENTE");

            // Validar inserción en usuario_detalle con los datos formateados (.trim() y concatenación)
            Mockito.verify(jdbc, Mockito.times(1)).update(
                    eq("INSERT INTO usuario_detalle (id_usuario, nombre_completo, pais, telefono, plataforma, dni) VALUES (?, ?, 'Perú', ?, 'WEB', ?)"),
                    eq(150),
                    eq("Erik Smit Ventura Hernández"),
                    eq("999888777"),
                    eq("99999999")
            );
        }
    }

    // ═══════════════════════════════════════════════════
    //  2. PRUEBAS PARA LOS MÉTODOS DE LISTADO (PANEL)
    // ═══════════════════════════════════════════════════

    @Test
    public void listarActivos_DebeRetornarListaDeUsuariosConCargosFormateados() {
        // Arrange
        UsuarioDTO.PanelItem usuarioMock = new UsuarioDTO.PanelItem(10, "Carlos Fuentes", "44332211", "Gerente general", "GER001", "carlos@mail.com", "GERENTE");
        Mockito.when(jdbc.query(anyString(), any(RowMapper.class))).thenReturn(List.of(usuarioMock));

        // Act
        List<UsuarioDTO.PanelItem> resultado = servicioUsuario.listarActivos();

        // Assert
        assertThat(resultado).isNotEmpty().hasSize(1);
        assertThat(resultado.get(0).getCargo()).isEqualTo("Gerente general");
        assertThat(resultado.get(0).getId()).isEqualTo(10);
    }

    @Test
    public void listarEliminados_DebeRetornarListaDeUsuariosInactivos() {
        // Arrange
        UsuarioDTO.PanelItem usuarioMock = new UsuarioDTO.PanelItem(11, "Juan Inactivo", "00112233", "Empleado", "EMP005", "juan@mail.com", "EMPLEADO");
        Mockito.when(jdbc.query(anyString(), any(RowMapper.class))).thenReturn(List.of(usuarioMock));

        // Act
        List<UsuarioDTO.PanelItem> resultado = servicioUsuario.listarEliminados();

        // Assert
        assertThat(resultado).isNotEmpty().hasSize(1);
        assertThat(resultado.get(0).getCargo()).isEqualTo("Empleado");
        assertThat(resultado.get(0).getCodigo()).isEqualTo("EMP005");
    }

    // Helper para simplificar matcheo de strings parciales en los logs/consultas mockeadas
    private String contains(String substring) {
        return Mockito.contains(substring);
    }
}
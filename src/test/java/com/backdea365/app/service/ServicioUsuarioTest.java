package com.backdea365.app.service;

import com.backdea365.app.dto.UsuarioDTO;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;

@ExtendWith(MockitoExtension.class)
public class ServicioUsuarioTest {

    @Mock
    private JdbcTemplate jdbc;

    @Mock
    private PasswordEncoder encoder;

    @InjectMocks
    private ServicioUsuario servicioUsuario;

    @Test
    public void crearUsuario_DebeLanzarBadRequest_CuandoRolEsInvalido() {
        UsuarioDTO.CrearRequest request = new UsuarioDTO.CrearRequest();
        // El servicio valida: correo → dni → nombreCompleto → rol
        // Hay que pasar los tres primeros para llegar a la validación del rol
        request.setCorreo("test@mail.com");
        request.setDni("12345678");
        request.setNombreCompleto("Juan");
        request.setRol("INVITADO");

        assertThatThrownBy(() -> servicioUsuario.crearUsuario(request))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("Rol inválido")
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    public void crearUsuario_DebeLanzarConflict_CuandoCorreoDuplicado() {
        UsuarioDTO.CrearRequest request = new UsuarioDTO.CrearRequest();
        // Hay que pasar correo, dni y nombreCompleto para superar las Preconditions
        // y llegar al chequeo de duplicado de correo
        request.setCorreo("test@mail.com");
        request.setDni("12345678");
        request.setNombreCompleto("Juan");
        request.setRol("EMPLEADO");

        // El servicio busca duplicado de correo con: SELECT COUNT(*) FROM usuarios_login WHERE correo = ?
        Mockito.when(jdbc.queryForObject(contains("usuarios_login"), eq(Integer.class), any()))
                .thenReturn(1);

        assertThatThrownBy(() -> servicioUsuario.crearUsuario(request))
                .isInstanceOf(ResponseStatusException.class)
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    public void crearUsuario_DebeGuardarUsuario_CuandoDatosValidos() {
        UsuarioDTO.CrearRequest request = new UsuarioDTO.CrearRequest();
        request.setRol("GERENTE");
        request.setCorreo("gerente@mail.com");
        request.setDni("12345678");
        request.setNombreCompleto("Juan");
        request.setApellidoCompleto("Perez");
        request.setContrasena("Pass123!");
        request.setTelefono("999888777");

        // correo duplicado → 0 (no existe)
        Mockito.when(jdbc.queryForObject(contains("usuarios_login"), eq(Integer.class), any()))
                .thenReturn(0);
        // dni duplicado → 0 (no existe)
        Mockito.when(jdbc.queryForObject(contains("usuario_detalle"), eq(Integer.class), any()))
                .thenReturn(0);
        // generarCodigo: MAX actual = 1 → siguiente será GER002
        Mockito.when(jdbc.queryForObject(contains("SUBSTRING"), eq(Integer.class), anyString()))
                .thenReturn(1);

        Mockito.when(encoder.encode(anyString())).thenReturn("hash");

        try (MockedConstruction<GeneratedKeyHolder> mockedKh = Mockito.mockConstruction(GeneratedKeyHolder.class,
                (mock, context) -> Mockito.when(mock.getKey()).thenReturn(10))) {

            UsuarioDTO.CrearResponse response = servicioUsuario.crearUsuario(request);

            assertThat(response).isNotNull();
            assertThat(response.getId()).isEqualTo(10);
            assertThat(response.getCodigo()).isEqualTo("GER002");
        }
    }

    @Test
    public void listarActivos_DebeRetornarLista() {
        UsuarioDTO.PanelItem item = new UsuarioDTO.PanelItem(
                1, "Test", "123", "Empleado", "EMP001", "a@a.com", "EMPLEADO"
        );
        // El servicio llama jdbc.query(sql, rowMapper, activo ? 1 : 0)
        // Es decir, tres argumentos: String, RowMapper, Object vararg
        Mockito.when(jdbc.query(anyString(), any(RowMapper.class), eq(1)))
                .thenReturn(List.of(item));

        List<UsuarioDTO.PanelItem> resultado = servicioUsuario.listarActivos();

        assertThat(resultado).hasSize(1);
        assertThat(resultado.get(0).getNombre()).isEqualTo("Test");
    }
}
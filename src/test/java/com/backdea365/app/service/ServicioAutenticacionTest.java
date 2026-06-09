package com.backdea365.app.service;

import com.backdea365.app.dto.AuthDTO;
import com.backdea365.app.model.UsuarioLogin;
import com.backdea365.app.repository.RepositorioUsuario;
import com.backdea365.app.security.UtilJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

import java.lang.reflect.Method;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;

@ExtendWith(MockitoExtension.class)
public class ServicioAutenticacionTest {

    @Mock
    private RepositorioUsuario repositorioUsuario;

    @Mock
    private UtilJWT utilJWT;

    @Mock
    private PasswordEncoder encoder;

    @Mock
    private JdbcTemplate jdbc;

    @InjectMocks
    private ServicioAutenticacion servicioAutenticacion;

    @BeforeEach
    public void setUp() throws Exception {
        // Inicializa manualmente el caché de Guava (@PostConstruct) para el entorno de Mockito
        Method method = ServicioAutenticacion.class.getDeclaredMethod("inicializarCache");
        method.setAccessible(true);
        method.invoke(servicioAutenticacion);
    }

    // ═══════════════════════════════════════════════════
    //  1. ESCENARIOS DE ERROR (404 / 401)
    // ═══════════════════════════════════════════════════

    @Test
    public void login_DebeLanzarNotFound_CuandoCodigoNoExiste() {
        AuthDTO.LoginRequest request = new AuthDTO.LoginRequest();
        request.setCodigo("EMP999");
        request.setPassword("clave123");

        Mockito.when(repositorioUsuario.buscarPorCodigo("EMP999"))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> servicioAutenticacion.login(request))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("Codigo no encontrado")
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);

        Mockito.verifyNoInteractions(encoder, utilJWT, jdbc);
    }

    @Test
    public void login_DebeLanzarUnauthorized_CuandoContrasenaEsIncorrecta() {
        AuthDTO.LoginRequest request = new AuthDTO.LoginRequest();
        request.setCodigo("EMP001");
        request.setPassword("clave_erronea");

        UsuarioLogin usuarioMock = new UsuarioLogin();
        usuarioMock.setCodigo("EMP001");
        usuarioMock.setClaveHash("$2a$10$hashEncriptadoBCryptDePrueba");

        Mockito.when(repositorioUsuario.buscarPorCodigo("EMP001"))
                .thenReturn(Optional.of(usuarioMock));

        Mockito.when(encoder.matches("clave_erronea", usuarioMock.getClaveHash()))
                .thenReturn(false);

        assertThatThrownBy(() -> servicioAutenticacion.login(request))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("Contrasena incorrecta")
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);

        Mockito.verifyNoInteractions(utilJWT, jdbc);
    }

    // ═══════════════════════════════════════════════════
    //  2. ESCENARIOS EXITOSOS Y LOGICA DE CACHÉ (200 OK)
    // ═══════════════════════════════════════════════════

    @Test
    public void login_DebeRetornarResponseYConsultarBD_CuandoEsCredencialValidaYCacheMiss() {
        AuthDTO.LoginRequest request = new AuthDTO.LoginRequest();
        request.setCodigo("EMP001");
        request.setPassword("clave123");

        UsuarioLogin usuarioMock = new UsuarioLogin();
        usuarioMock.setIdUsuario(10);
        usuarioMock.setCodigo("EMP001");
        usuarioMock.setClaveHash("$2a$10$hashEncriptado");
        usuarioMock.setRol(UsuarioLogin.Rol.ADMINISTRADOR);

        Mockito.when(repositorioUsuario.buscarPorCodigo("EMP001"))
                .thenReturn(Optional.of(usuarioMock));
        Mockito.when(encoder.matches("clave123", usuarioMock.getClaveHash()))
                .thenReturn(true);
        Mockito.when(utilJWT.generarToken("EMP001", "ADMINISTRADOR"))
                .thenReturn("jwt-token-falso-xyz");

        Mockito.when(jdbc.queryForObject(anyString(), eq(String.class), eq(10)))
                .thenReturn("Erik Smit Ventura");

        AuthDTO.LoginResponse respuesta = servicioAutenticacion.login(request);

        assertThat(respuesta).isNotNull();
        assertThat(respuesta.getToken()).isEqualTo("jwt-token-falso-xyz");
        assertThat(respuesta.getNombre()).isEqualTo("Erik Smit Ventura"); // Corregido: .getNombreCompleto() -> .getNombre()
        assertThat(respuesta.getRol()).isEqualTo("ADMINISTRADOR");

        Mockito.verify(jdbc, Mockito.times(1))
                .queryForObject(anyString(), eq(String.class), eq(10));
    }

    @Test
    public void login_DebeEvitarQueryADB_CuandoElUsuarioYaEstaEnCacheHit() {
        AuthDTO.LoginRequest request = new AuthDTO.LoginRequest();
        request.setCodigo("EMP001");
        request.setPassword("clave123");

        UsuarioLogin usuarioMock = new UsuarioLogin();
        usuarioMock.setIdUsuario(10);
        usuarioMock.setCodigo("EMP001");
        usuarioMock.setClaveHash("$2a$10$hashEncriptado");
        usuarioMock.setRol(UsuarioLogin.Rol.ADMINISTRADOR);

        Mockito.when(repositorioUsuario.buscarPorCodigo("EMP001"))
                .thenReturn(Optional.of(usuarioMock));
        Mockito.when(encoder.matches("clave123", usuarioMock.getClaveHash()))
                .thenReturn(true);
        Mockito.when(utilJWT.generarToken("EMP001", "ADMINISTRADOR"))
                .thenReturn("jwt-token-falso-xyz");

        // Primer Login (Puebla el caché de Guava)
        Mockito.when(jdbc.queryForObject(anyString(), eq(String.class), eq(10)))
                .thenReturn("Erik Smit Ventura");
        servicioAutenticacion.login(request);

        // Act: Segundo Login consecutivo
        AuthDTO.LoginResponse segundaRespuesta = servicioAutenticacion.login(request);

        // Assert
        assertThat(segundaRespuesta.getNombre()).isEqualTo("Erik Smit Ventura"); // Corregido: .getNombreCompleto() -> .getNombre()

        // Verifica que la consulta SQL a usuario_detalle solo se ejecutó en el primer login
        Mockito.verify(jdbc, Mockito.times(1))
                .queryForObject(anyString(), eq(String.class), eq(10));
    }

    @Test
    public void login_DebeUsarCodigoComoNombre_CuandoBDExcepcionaONoTienePerfil() {
        AuthDTO.LoginRequest request = new AuthDTO.LoginRequest();
        request.setCodigo("EMP002");
        request.setPassword("clave123");

        UsuarioLogin usuarioMock = new UsuarioLogin();
        usuarioMock.setIdUsuario(20);
        usuarioMock.setCodigo("EMP002");
        usuarioMock.setClaveHash("$2a$10$hashEncriptado");
        usuarioMock.setRol(UsuarioLogin.Rol.EMPLEADO);

        Mockito.when(repositorioUsuario.buscarPorCodigo("EMP002"))
                .thenReturn(Optional.of(usuarioMock));
        Mockito.when(encoder.matches("clave123", usuarioMock.getClaveHash()))
                .thenReturn(true);
        Mockito.when(utilJWT.generarToken("EMP002", "EMPLEADO"))
                .thenReturn("jwt-token-valido");

        Mockito.when(jdbc.queryForObject(anyString(), eq(String.class), eq(20)))
                .thenThrow(new org.springframework.dao.EmptyResultDataAccessException(1));

        AuthDTO.LoginResponse respuesta = servicioAutenticacion.login(request);

        // Valida que caiga en el fallback usando el código de empleado como nombre
        assertThat(respuesta.getNombre()).isEqualTo("EMP002"); // Corregido: .getNombreCompleto() -> .getNombre()
    }
}
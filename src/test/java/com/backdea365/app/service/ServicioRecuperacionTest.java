package com.backdea365.app.service;

import com.backdea365.app.dto.RecuperarDTO;
import com.backdea365.app.model.ResetPassword;
import com.backdea365.app.model.UsuarioLogin;
import com.backdea365.app.repository.RepositorioResetPassword;
import com.backdea365.app.repository.RepositorioUsuario;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;

@ExtendWith(MockitoExtension.class)
public class ServicioRecuperacionTest {

    @Mock
    private RepositorioUsuario repoUsuario;

    @Mock
    private RepositorioResetPassword repoReset;

    @Mock
    private PasswordEncoder encoder;

    @InjectMocks
    private ServicioRecuperacion servicioRecuperacion;

    @BeforeEach
    public void setUp() {
        // Inicializamos las propiedades de configuración inyectadas por @Value
        ReflectionTestUtils.setField(servicioRecuperacion, "resendApiKey", "re_test_123456789");
        ReflectionTestUtils.setField(servicioRecuperacion, "resendFrom", "onboarding@resend.dev");
    }

    // ═══════════════════════════════════════════════════
    //  1. PRUEBAS PARA PASO 1: SOLICITAR CÓDIGO
    // ═══════════════════════════════════════════════════

    @Test
    public void solicitarCodigo_DebeLanzarNotFound_CuandoElCorreoNoExiste() {
        // Arrange
        RecuperarDTO.SolicitarRequest request = new RecuperarDTO.SolicitarRequest();
        request.setCorreo("noexiste@mail.com");

        Mockito.when(repoUsuario.buscarPorCorreo("noexiste@mail.com")).thenReturn(Optional.empty());

        // Act & Assert
        assertThatThrownBy(() -> servicioRecuperacion.solicitarCodigo(request))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("No encontramos una cuenta con ese correo.")
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);

        Mockito.verify(repoReset, Mockito.never()).invalidarCodigos(anyString());
        Mockito.verify(repoReset, Mockito.never()).save(any(ResetPassword.class));
    }

    @Test
    public void solicitarCodigo_DebeGuardarCodigoYEnviarCorreo_CuandoElCorreoExiste() {
        // Arrange
        RecuperarDTO.SolicitarRequest request = new RecuperarDTO.SolicitarRequest();
        request.setCorreo("erik@mail.com");

        Mockito.when(repoUsuario.buscarPorCorreo("erik@mail.com")).thenReturn(Optional.of(new UsuarioLogin()));

        // Aislamos la llamada de red interceptando la instanciación de 'new RestTemplate()'
        try (MockedConstruction<RestTemplate> mockedRestTemplate = Mockito.mockConstruction(RestTemplate.class,
                (mock, context) -> {
                    Mockito.when(mock.postForEntity(anyString(), any(), eq(Map.class)))
                            .thenReturn(new ResponseEntity<>(Map.of(), HttpStatus.OK));
                })) {

            // Act
            servicioRecuperacion.solicitarCodigo(request);

            // Assert
            Mockito.verify(repoReset, Mockito.times(1)).invalidarCodigos("erik@mail.com");
            Mockito.verify(repoReset, Mockito.times(1)).save(any(ResetPassword.class));
            assertThat(mockedRestTemplate.constructed()).hasSize(1);
        }
    }

    @Test
    public void solicitarCodigo_DebeLanzarInternalServerError_CuandoLaApiResendFalla() {
        // Arrange
        RecuperarDTO.SolicitarRequest request = new RecuperarDTO.SolicitarRequest();
        request.setCorreo("erik@mail.com");

        Mockito.when(repoUsuario.buscarPorCorreo("erik@mail.com")).thenReturn(Optional.of(new UsuarioLogin()));

        // Simulamos que la llamada externa por HTTP lanza una excepción inesperada
        try (MockedConstruction<RestTemplate> mockedRestTemplate = Mockito.mockConstruction(RestTemplate.class,
                (mock, context) -> {
                    Mockito.when(mock.postForEntity(anyString(), any(), eq(Map.class)))
                            .thenThrow(new RuntimeException("API Resend Offline"));
                })) {

            // Act & Assert
            assertThatThrownBy(() -> servicioRecuperacion.solicitarCodigo(request))
                    .isInstanceOf(ResponseStatusException.class)
                    .hasMessageContaining("Error al enviar el correo")
                    .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                    .isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    // ═══════════════════════════════════════════════════
    //  2. PRUEBAS PARA PASO 2: VERIFICAR CÓDIGO
    // ═══════════════════════════════════════════════════

    @Test
    public void verificarCodigo_DebeLanzarBadRequest_CuandoNoHayCodigoVigente() {
        // Arrange
        RecuperarDTO.VerificarRequest request = new RecuperarDTO.VerificarRequest();
        request.setCorreo("erik@mail.com");
        request.setCodigo("123456");

        Mockito.when(repoReset.buscarCodigoVigente(eq("erik@mail.com"), any(LocalDateTime.class)))
                .thenReturn(Optional.empty());

        // Act & Assert
        assertThatThrownBy(() -> servicioRecuperacion.verificarCodigo(request))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("El codigo es incorrecto o ya expiro.")
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    public void verificarCodigo_DebeLanzarBadRequest_CuandoElCodigoNoCoincide() {
        // Arrange
        RecuperarDTO.VerificarRequest request = new RecuperarDTO.VerificarRequest();
        request.setCorreo("erik@mail.com");
        request.setCodigo("999999"); // Código erróneo enviado por el cliente

        ResetPassword resetMock = new ResetPassword();
        resetMock.setCodigo("123456"); // Código real guardado en BD

        Mockito.when(repoReset.buscarCodigoVigente(eq("erik@mail.com"), any(LocalDateTime.class)))
                .thenReturn(Optional.of(resetMock));

        // Act & Assert
        assertThatThrownBy(() -> servicioRecuperacion.verificarCodigo(request))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("El codigo es incorrecto o ya expiro.")
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    public void verificarCodigo_DebeFinalizarSinExcepcion_CuandoElFlujoEsCorrecto() {
        // Arrange
        RecuperarDTO.VerificarRequest request = new RecuperarDTO.VerificarRequest();
        request.setCorreo("erik@mail.com");
        request.setCodigo("123456");

        ResetPassword resetMock = new ResetPassword();
        resetMock.setCodigo("123456");

        Mockito.when(repoReset.buscarCodigoVigente(eq("erik@mail.com"), any(LocalDateTime.class)))
                .thenReturn(Optional.of(resetMock));

        // Act & Assert (No debe lanzar ninguna excepción)
        servicioRecuperacion.verificarCodigo(request);
    }

    // ═══════════════════════════════════════════════════
    //  3. PRUEBAS PARA PASO 3: CAMBIAR PASSWORD
    // ═══════════════════════════════════════════════════

    @Test
    public void cambiarPassword_DebeLanzarBadRequest_CuandoCodigoNoExisteOVencido() {
        // Arrange
        RecuperarDTO.CambiarRequest request = new RecuperarDTO.CambiarRequest();
        request.setCorreo("erik@mail.com");
        request.setCodigo("123456");

        Mockito.when(repoReset.buscarCodigoVigente(eq("erik@mail.com"), any(LocalDateTime.class)))
                .thenReturn(Optional.empty());

        // Act & Assert
        assertThatThrownBy(() -> servicioRecuperacion.cambiarPassword(request))
                .isInstanceOf(ResponseStatusException.class)
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    public void cambiarPassword_DebeLanzarNotFound_CuandoElUsuarioFueEliminadoORemovido() {
        // Arrange
        RecuperarDTO.CambiarRequest request = new RecuperarDTO.CambiarRequest();
        request.setCorreo("erik@mail.com");
        request.setCodigo("123456");

        ResetPassword resetMock = new ResetPassword();
        resetMock.setCodigo("123456");

        Mockito.when(repoReset.buscarCodigoVigente(eq("erik@mail.com"), any(LocalDateTime.class)))
                .thenReturn(Optional.of(resetMock));
        Mockito.when(repoUsuario.buscarPorCorreo("erik@mail.com")).thenReturn(Optional.empty());

        // Act & Assert
        assertThatThrownBy(() -> servicioRecuperacion.cambiarPassword(request))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("Usuario no encontrado.")
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    public void cambiarPassword_DebeActualizarPasswordYMarcarCodigoComoUsado_CuandoTodoEsValido() {
        // Arrange
        RecuperarDTO.CambiarRequest request = new RecuperarDTO.CambiarRequest();
        request.setCorreo("erik@mail.com");
        request.setCodigo("123456");
        request.setNuevaPassword("NuevaSegura123!");

        ResetPassword resetMock = new ResetPassword();
        resetMock.setCodigo("123456");
        resetMock.setUsado(false);

        UsuarioLogin usuarioMock = new UsuarioLogin();

        Mockito.when(repoReset.buscarCodigoVigente(eq("erik@mail.com"), any(LocalDateTime.class)))
                .thenReturn(Optional.of(resetMock));
        Mockito.when(repoUsuario.buscarPorCorreo("erik@mail.com")).thenReturn(Optional.of(usuarioMock));
        Mockito.when(encoder.encode("NuevaSegura123!")).thenReturn("$2a$10$EncryptedHashNewPassword");

        // Act
        servicioRecuperacion.cambiarPassword(request);

        // Assert
        assertThat(usuarioMock.getClaveHash()).isEqualTo("$2a$10$EncryptedHashNewPassword");

        // CORREGIDO: Se cambia isUsado() por getUsado() para alinearse con el Wrapper Boolean de Lombok
        assertThat(resetMock.getUsado()).isTrue();

        Mockito.verify(repoUsuario, Mockito.times(1)).save(usuarioMock);
        Mockito.verify(repoReset, Mockito.times(1)).save(resetMock);
    }
}
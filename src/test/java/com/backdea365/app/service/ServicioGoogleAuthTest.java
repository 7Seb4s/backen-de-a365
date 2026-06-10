package com.backdea365.app.service;

import com.backdea365.app.dto.AuthDTO;
import com.backdea365.app.model.UsuarioLogin;
import com.backdea365.app.repository.RepositorioUsuario;
import com.backdea365.app.security.UtilJWT;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;

@ExtendWith(MockitoExtension.class)
public class ServicioGoogleAuthTest {

    @Mock
    private RepositorioUsuario repositorioUsuario;

    @Mock
    private UtilJWT utilJWT;

    @Mock
    private JdbcTemplate jdbc;

    @InjectMocks
    private ServicioGoogleAuth servicioGoogleAuth;

    @BeforeEach
    public void setUp() {
        // Inyectamos el valor de la propiedad @Value de forma manual sin levantar el contexto de Spring
        ReflectionTestUtils.setField(servicioGoogleAuth, "googleClientId", "mock-google-client-id-xyz.apps.googleusercontent.com");
    }

    // ═══════════════════════════════════════════════════
    //  1. ESCENARIOS DE ERROR (401 / 404 / 403)
    // ═══════════════════════════════════════════════════

    @Test
    public void loginConGoogle_DebeLanzarUnauthorized_CuandoTokenDeGoogleEsInvalido() {
        String tokenInvalido = "google-token-falso-o-expirado";

        // Interceptamos la creación interna de GoogleIdTokenVerifier para simular que devuelve null (token inválido)
        try (MockedConstruction<GoogleIdTokenVerifier> mocked = Mockito.mockConstruction(GoogleIdTokenVerifier.class,
                (mock, context) -> Mockito.when(mock.verify(tokenInvalido)).thenReturn(null))) {

            assertThatThrownBy(() -> servicioGoogleAuth.loginConGoogle(tokenInvalido))
                    .isInstanceOf(ResponseStatusException.class)
                    .hasMessageContaining("Token de Google invalido o expirado")
                    .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                    .isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        // Validamos aislamiento: No se debió buscar en la base de datos
        Mockito.verifyNoInteractions(repositorioUsuario, utilJWT, jdbc);
    }

    @Test
    public void loginConGoogle_DebeLanzarNotFound_CuandoCorreoNoEstaRegistradoEnElSistema() {
        String tokenValido = "google-token-legitimo";
        String correoNoRegistrado = "usuario.externo@gmail.com";

        // Preparamos el payload falso de Google
        GoogleIdToken mockIdToken = Mockito.mock(GoogleIdToken.class);
        GoogleIdToken.Payload payload = new GoogleIdToken.Payload();
        payload.setEmail(correoNoRegistrado);
        Mockito.when(mockIdToken.getPayload()).thenReturn(payload);

        // Simulamos que el repositorio no encuentra al usuario por este correo
        Mockito.when(repositorioUsuario.buscarPorCorreo(correoNoRegistrado))
                .thenReturn(Optional.empty());

        try (MockedConstruction<GoogleIdTokenVerifier> mocked = Mockito.mockConstruction(GoogleIdTokenVerifier.class,
                (mock, context) -> Mockito.when(mock.verify(tokenValido)).thenReturn(mockIdToken))) {

            assertThatThrownBy(() -> servicioGoogleAuth.loginConGoogle(tokenValido))
                    .isInstanceOf(ResponseStatusException.class)
                    .hasMessageContaining("no esta registrado en el sistema")
                    .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                    .isEqualTo(HttpStatus.NOT_FOUND);
        }

        Mockito.verifyNoInteractions(utilJWT, jdbc);
    }

    @Test
    public void loginConGoogle_DebeLanzarForbidden_CuandoUsuarioEstaDesactivado() {
        String tokenValido = "google-token-legitimo";
        String correoInactivo = "erik.ventura@impulsaa365.com";

        GoogleIdToken mockIdToken = Mockito.mock(GoogleIdToken.class);
        GoogleIdToken.Payload payload = new GoogleIdToken.Payload();
        payload.setEmail(correoInactivo);
        Mockito.when(mockIdToken.getPayload()).thenReturn(payload);

        // Creamos un usuario mock que se encuentra desactivado (activo = false)
        UsuarioLogin usuarioInactivo = new UsuarioLogin();
        usuarioInactivo.setCorreo(correoInactivo);
        usuarioInactivo.setActivo(false);

        Mockito.when(repositorioUsuario.buscarPorCorreo(correoInactivo))
                .thenReturn(Optional.of(usuarioInactivo));

        try (MockedConstruction<GoogleIdTokenVerifier> mocked = Mockito.mockConstruction(GoogleIdTokenVerifier.class,
                (mock, context) -> Mockito.when(mock.verify(tokenValido)).thenReturn(mockIdToken))) {

            assertThatThrownBy(() -> servicioGoogleAuth.loginConGoogle(tokenValido))
                    .isInstanceOf(ResponseStatusException.class)
                    .hasMessageContaining("Tu cuenta esta desactivada")
                    .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                    .isEqualTo(HttpStatus.FORBIDDEN);
        }

        Mockito.verifyNoInteractions(utilJWT, jdbc);
    }

    // ═══════════════════════════════════════════════════
    //  2. ESCENARIO EXITOSO (200 OK)
    // ═══════════════════════════════════════════════════

    @Test
    public void loginConGoogle_DebeRetornarLoginResponse_CuandoCredencialesYUsuarioSonValidos() {
        String tokenValido = "google-token-legitimo";
        String correoValido = "erik.ventura@impulsaa365.com";

        GoogleIdToken mockIdToken = Mockito.mock(GoogleIdToken.class);
        GoogleIdToken.Payload payload = new GoogleIdToken.Payload();
        payload.setEmail(correoValido);
        Mockito.when(mockIdToken.getPayload()).thenReturn(payload);

        UsuarioLogin usuarioMock = new UsuarioLogin();
        usuarioMock.setIdUsuario(77);
        usuarioMock.setCodigo("EMP007");
        usuarioMock.setCorreo(correoValido);
        usuarioMock.setRol(UsuarioLogin.Rol.GERENTE);
        usuarioMock.setActivo(true);

        // Definimos comportamientos de los mocks
        Mockito.when(repositorioUsuario.buscarPorCorreo(correoValido))
                .thenReturn(Optional.of(usuarioMock));
        Mockito.when(jdbc.queryForObject(anyString(), eq(String.class), eq(77)))
                .thenReturn("Erik Smit Ventura")   // nombre
                .thenReturn(null);                  // fotoUrl
        Mockito.when(utilJWT.generarToken("EMP007", "GERENTE"))
                .thenReturn("jwt-propio-firmado-hs512");

        AuthDTO.LoginResponse respuesta;

        try (MockedConstruction<GoogleIdTokenVerifier> mocked = Mockito.mockConstruction(GoogleIdTokenVerifier.class,
                (mock, context) -> Mockito.when(mock.verify(tokenValido)).thenReturn(mockIdToken))) {

            // Ejecución del flujo principal
            respuesta = servicioGoogleAuth.loginConGoogle(tokenValido);
        }

        // Verificaciones finales de la estructura del DTO de salida
        assertThat(respuesta).isNotNull();
        assertThat(respuesta.getToken()).isEqualTo("jwt-propio-firmado-hs512");
        assertThat(respuesta.getTipo()).isEqualTo("Bearer");
        assertThat(respuesta.getId()).isEqualTo(77);
        assertThat(respuesta.getCodigo()).isEqualTo("EMP007");
        assertThat(respuesta.getNombre()).isEqualTo("Erik Smit Ventura");
        assertThat(respuesta.getRol()).isEqualTo("GERENTE");

        // 2 llamadas: 1 para nombre + 1 para foto_url
        Mockito.verify(jdbc, Mockito.times(2))
                .queryForObject(anyString(), eq(String.class), eq(77));
    }
}
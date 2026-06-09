package com.backdea365.app.service;

import com.backdea365.app.dto.PerfilDTO;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;

@ExtendWith(MockitoExtension.class)
public class ServicioPerfilTest {

    @Mock
    private JdbcTemplate jdbc;

    @Mock
    private PasswordEncoder encoder;

    @InjectMocks
    private ServicioPerfil servicioPerfil;

    // ═══════════════════════════════════════════════════
    //  1. PRUEBAS PARA EL MÉTODO OBTENER PERFIL
    // ═══════════════════════════════════════════════════

    @Test
    public void obtenerPerfil_DebeRetornarPerfil_CuandoUsuarioExisteYEstaActivo() {
        Integer idUsuario = 15;
        PerfilDTO.PerfilResponse mockPerfil = new PerfilDTO.PerfilResponse(
                "EMP15", "Erik Smit Ventura", "erik@mail.com", "Av. Central 123", "987654321", "74859612", null
        );

        Mockito.when(jdbc.query(anyString(), any(RowMapper.class), eq(idUsuario)))
                .thenReturn(List.of(mockPerfil));

        PerfilDTO.PerfilResponse resultado = servicioPerfil.obtenerPerfil(idUsuario);

        assertThat(resultado).isNotNull();
        assertThat(resultado.getCodigoTrabajador()).isEqualTo("EMP15");
        assertThat(resultado.getNombreCompleto()).isEqualTo("Erik Smit Ventura");
        assertThat(resultado.getCorreo()).isEqualTo("erik@mail.com");
    }

    @Test
    public void obtenerPerfil_DebeLanzarNotFound_CuandoUsuarioNoExisteOEstaInactivo() {
        Integer idUsuario = 99;

        Mockito.when(jdbc.query(anyString(), any(RowMapper.class), eq(idUsuario)))
                .thenReturn(Collections.emptyList());

        assertThatThrownBy(() -> servicioPerfil.obtenerPerfil(idUsuario))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("Usuario no encontrado")
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
    }

    // ═══════════════════════════════════════════════════
    //  2. PRUEBAS PARA EL MÉTODO ACTUALIZAR PERFIL
    // ═══════════════════════════════════════════════════

    @Test
    public void actualizarPerfil_DebeLanzarConflict_CuandoElCorreoYaPerteneceAOtroUsuario() {
        Integer idUsuario = 15;
        PerfilDTO.ActualizarRequest request = new PerfilDTO.ActualizarRequest();
        request.setCorreo("duplicado@mail.com");
        request.setDni("74859612");

        Mockito.when(jdbc.queryForObject(eq("SELECT COUNT(*) FROM usuarios_login WHERE correo = ? AND id_usuario <> ?"), eq(Integer.class), eq("duplicado@mail.com"), eq(idUsuario)))
                .thenReturn(1);

        assertThatThrownBy(() -> servicioPerfil.actualizarPerfil(idUsuario, request))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("El correo ya esta registrado por otro usuario")
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.CONFLICT);

        Mockito.verify(jdbc, Mockito.never()).update(anyString(), any(), any());
    }

    @Test
    public void actualizarPerfil_DebeLanzarConflict_CuandoElDniYaPerteneceAOtroUsuario() {
        Integer idUsuario = 15;
        PerfilDTO.ActualizarRequest request = new PerfilDTO.ActualizarRequest();
        request.setCorreo("unico@mail.com");
        request.setDni("88888888");

        Mockito.when(jdbc.queryForObject(eq("SELECT COUNT(*) FROM usuarios_login WHERE correo = ? AND id_usuario <> ?"), eq(Integer.class), eq("unico@mail.com"), eq(idUsuario)))
                .thenReturn(0);
        Mockito.when(jdbc.queryForObject(eq("SELECT COUNT(*) FROM usuario_detalle WHERE dni = ? AND id_usuario <> ?"), eq(Integer.class), eq("88888888"), eq(idUsuario)))
                .thenReturn(1);

        assertThatThrownBy(() -> servicioPerfil.actualizarPerfil(idUsuario, request))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("El DNI ya esta registrado por otro usuario")
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    public void actualizarPerfil_DebeGuardarCambios_CuandoDatosSonUnicosYValidos() {
        Integer idUsuario = 15;
        PerfilDTO.ActualizarRequest request = new PerfilDTO.ActualizarRequest();
        request.setNombreCompleto("  Erik Smit Ventura Hernandez  ");
        request.setCorreo("  ERIK.VENTURA@MAIL.COM  ");
        request.setTelefono("987654321");
        request.setDireccion("  Calle Las Acacias 456  ");
        request.setDni("74859612");

        Mockito.when(jdbc.queryForObject(anyString(), eq(Integer.class), eq("erik.ventura@mail.com"), eq(idUsuario))).thenReturn(0);
        Mockito.when(jdbc.queryForObject(anyString(), eq(Integer.class), eq("74859612"), eq(idUsuario))).thenReturn(0);

        PerfilDTO.OperacionResponse respuesta = servicioPerfil.actualizarPerfil(idUsuario, request);

        assertThat(respuesta.getMensaje()).contains("Tu perfil ha sido actualizado correctamente");

        Mockito.verify(jdbc, Mockito.times(1)).update(
                eq("UPDATE usuarios_login SET correo = ?, actualizado_en = NOW() WHERE id_usuario = ? AND activo = 1"),
                eq("erik.ventura@mail.com"),
                eq(idUsuario)
        );

        Mockito.verify(jdbc, Mockito.times(1)).update(
                anyString(),
                eq(idUsuario),
                eq("Erik Smit Ventura Hernandez"),
                eq("987654321"),
                eq("Calle Las Acacias 456"),
                eq("74859612")
        );
    }

    // ═══════════════════════════════════════════════════
    //  3. PRUEBAS PARA CAMBIAR CONTRASEÑA
    // ═══════════════════════════════════════════════════

    @Test
    public void cambiarContrasena_DebeLanzarBadRequest_CuandoNuevaContrasenaYConfirmacionNoCoinciden() {
        Integer idUsuario = 15;
        PerfilDTO.CambiarContrasenaRequest request = new PerfilDTO.CambiarContrasenaRequest();
        request.setContrasenaActual("Actual123!");
        request.setNuevaContrasena("Nueva123!");
        request.setConfirmarContrasena("Diferente123!");

        assertThatThrownBy(() -> servicioPerfil.cambiarContrasena(idUsuario, request))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("Las contrasenas no coinciden")
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    public void cambiarContrasena_DebeLanzarNotFound_CuandoUsuarioNoExisteAlBuscarHash() {
        Integer idUsuario = 99;
        PerfilDTO.CambiarContrasenaRequest request = new PerfilDTO.CambiarContrasenaRequest();
        request.setContrasenaActual("Actual123!");
        request.setNuevaContrasena("Nueva123!");
        request.setConfirmarContrasena("Nueva123!");

        Mockito.when(jdbc.queryForObject(anyString(), eq(String.class), eq(idUsuario)))
                .thenThrow(new org.springframework.dao.EmptyResultDataAccessException(1));

        assertThatThrownBy(() -> servicioPerfil.cambiarContrasena(idUsuario, request))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("Usuario no encontrado")
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    public void cambiarContrasena_DebeLanzarUnauthorized_CuandoContrasenaActualEsIncorrecta() {
        Integer idUsuario = 15;
        PerfilDTO.CambiarContrasenaRequest request = new PerfilDTO.CambiarContrasenaRequest();
        request.setContrasenaActual("ClaveIncorrecta123!");
        request.setNuevaContrasena("Nueva123!");
        request.setConfirmarContrasena("Nueva123!");

        String hashBd = "$2a$10$HashSimuladoDeBCryptDeLaContrasenaCorrecta";
        Mockito.when(jdbc.queryForObject(anyString(), eq(String.class), eq(idUsuario)))
                .thenReturn(hashBd);

        Mockito.when(encoder.matches("ClaveIncorrecta123!", hashBd)).thenReturn(false);

        assertThatThrownBy(() -> servicioPerfil.cambiarContrasena(idUsuario, request))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("La contrasena actual es incorrecta")
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    public void cambiarContrasena_DebeActualizarHash_CuandoContrasenaActualEsCorrecta() {
        Integer idUsuario = 15;
        PerfilDTO.CambiarContrasenaRequest request = new PerfilDTO.CambiarContrasenaRequest();
        request.setContrasenaActual("Correcta123!");
        request.setNuevaContrasena("NuevaClave123!");
        request.setConfirmarContrasena("NuevaClave123!");

        String hashViejo = "$2a$10$HashViejo";
        String hashNuevo = "$2a$10$HashNuevoCodificadoConBCrypt";

        Mockito.when(jdbc.queryForObject(anyString(), eq(String.class), eq(idUsuario)))
                .thenReturn(hashViejo);
        Mockito.when(encoder.matches("Correcta123!", hashViejo)).thenReturn(true);
        Mockito.when(encoder.encode("NuevaClave123!")).thenReturn(hashNuevo);

        PerfilDTO.OperacionResponse respuesta = servicioPerfil.cambiarContrasena(idUsuario, request);

        assertThat(respuesta.getMensaje()).contains("Tu contrasena ha sido actualizada correctamente");

        Mockito.verify(jdbc, Mockito.times(1)).update(
                eq("CALL sp_cambiar_clave(?, ?)"),
                eq(idUsuario),
                eq(hashNuevo)
        );
    }
}
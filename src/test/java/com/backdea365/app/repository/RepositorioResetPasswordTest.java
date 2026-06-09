package com.backdea365.app.repository;

import com.backdea365.app.model.ResetPassword;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase; // <-- IMPORTANTE
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE) // <-- ESTA LÍNEA EVITA TOCAR EL POM
public class RepositorioResetPasswordTest {

    @Autowired
    private RepositorioResetPassword repositorioResetPassword;

    @Autowired
    private TestEntityManager entityManager;

    @Test
    public void testBuscarCodigoVigente_DebeRetornarElCodigoMasRecienteYActivo() {
        String correoDestino = "erik.ventura@impulsaa365.com";
        LocalDateTime ahora = LocalDateTime.of(2026, 6, 8, 12, 0);

        ResetPassword codigoAntiguo = new ResetPassword();
        codigoAntiguo.setCorreo(correoDestino);
        codigoAntiguo.setCodigo("111111");
        codigoAntiguo.setExpiracion(ahora.plusMinutes(5));
        codigoAntiguo.setUsado(false);
        codigoAntiguo.setCreadoEn(ahora.minusMinutes(10));
        entityManager.persist(codigoAntiguo);

        ResetPassword codigoNuevo = new ResetPassword();
        codigoNuevo.setCorreo(correoDestino);
        codigoNuevo.setCodigo("222222");
        codigoNuevo.setExpiracion(ahora.plusMinutes(14));
        codigoNuevo.setUsado(false);
        codigoNuevo.setCreadoEn(ahora.minusMinutes(1));
        entityManager.persist(codigoNuevo);

        entityManager.flush();

        Optional<ResetPassword> resultado = repositorioResetPassword.buscarCodigoVigente(correoDestino, ahora);

        assertThat(resultado).isPresent();
        assertThat(resultado.get().getCodigo()).isEqualTo("222222");
        assertThat(resultado.get().getUsado()).isFalse();
    }

    @Test
    public void testBuscarCodigoVigente_CuandoEstaExpiradoOUsado_DebeRetornarVacio() {
        String correoDestino = "erik.ventura@impulsaa365.com";
        LocalDateTime ahora = LocalDateTime.of(2026, 6, 8, 12, 0);

        ResetPassword codigoUsado = new ResetPassword();
        codigoUsado.setCorreo(correoDestino);
        codigoUsado.setCodigo("333333");
        codigoUsado.setExpiracion(ahora.plusMinutes(10));
        codigoUsado.setUsado(true);
        codigoUsado.setCreadoEn(ahora.minusMinutes(2));
        entityManager.persist(codigoUsado);

        ResetPassword codigoExpirado = new ResetPassword();
        codigoExpirado.setCorreo(correoDestino);
        codigoExpirado.setCodigo("444444");
        codigoExpirado.setExpiracion(ahora.minusMinutes(1));
        codigoExpirado.setUsado(false);
        codigoExpirado.setCreadoEn(ahora.minusMinutes(16));
        entityManager.persist(codigoExpirado);

        entityManager.flush();

        Optional<ResetPassword> resultado = repositorioResetPassword.buscarCodigoVigente(correoDestino, ahora);

        assertThat(resultado).isEmpty();
    }

    @Test
    public void testInvalidarCodigos_DebeCambiarElEstadoUsadoATrueParaTodosLosCodigosDelCorreo() {
        String correoDestino = "erik.ventura@impulsaa365.com";
        String otroCorreo = "contacto@wica.pe";

        ResetPassword token1 = new ResetPassword();
        token1.setCorreo(correoDestino);
        token1.setCodigo("123456");
        token1.setExpiracion(LocalDateTime.now().plusMinutes(15));
        token1.setUsado(false);
        entityManager.persist(token1);

        ResetPassword token2 = new ResetPassword();
        token2.setCorreo(correoDestino);
        token2.setCodigo("654321");
        token2.setExpiracion(LocalDateTime.now().plusMinutes(15));
        token2.setUsado(false);
        entityManager.persist(token2);

        ResetPassword tokenAjeno = new ResetPassword();
        tokenAjeno.setCorreo(otroCorreo);
        tokenAjeno.setCodigo("999999");
        tokenAjeno.setExpiracion(LocalDateTime.now().plusMinutes(15));
        tokenAjeno.setUsado(false);
        entityManager.persist(tokenAjeno);

        entityManager.flush();

        repositorioResetPassword.invalidarCodigos(correoDestino);
        entityManager.clear();

        ResetPassword clonToken1 = repositorioResetPassword.findById(token1.getId()).orElseThrow();
        ResetPassword clonToken2 = repositorioResetPassword.findById(token2.getId()).orElseThrow();
        ResetPassword clonTokenAjeno = repositorioResetPassword.findById(tokenAjeno.getId()).orElseThrow();

        assertThat(clonToken1.getUsado()).isTrue();
        assertThat(clonToken2.getUsado()).isTrue();
        assertThat(clonTokenAjeno.getUsado()).isFalse();
    }
}
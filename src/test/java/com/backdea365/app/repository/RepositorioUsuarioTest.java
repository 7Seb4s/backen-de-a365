package com.backdea365.app.repository;

import com.backdea365.app.model.UsuarioLogin;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
public class RepositorioUsuarioTest {

    @Autowired
    private RepositorioUsuario repositorioUsuario;

    @Autowired
    private TestEntityManager entityManager;

    @Test
    public void testBuscarPorCorreo_DebeRetornarUsuario_CuandoElCorreoExiste() {
        // Arrange: Insertamos un usuario de prueba transaccional
        UsuarioLogin usuario = new UsuarioLogin();
        usuario.setCodigo("EMP999");
        usuario.setCorreo("test.usuario@impulsaa365.com");
        usuario.setClaveHash("$2a$10$abcdefghijklmnopqrstuvwxyz"); // Simulación hash BCrypt
        usuario.setRol(UsuarioLogin.Rol.ADMINISTRADOR);
        usuario.setActivo(true);

        entityManager.persist(usuario);
        entityManager.flush();

        // Act: Llamamos al método que ejecuta 'CALL sp_buscar_usuario_por_correo'
        Optional<UsuarioLogin> resultado = repositorioUsuario.buscarPorCorreo("test.usuario@impulsaa365.com");

        // Assert: Validamos que el SP devuelva correctamente la fila mapeada
        assertThat(resultado).isPresent();
        assertThat(resultado.get().getCodigo()).isEqualTo("EMP999");
        assertThat(resultado.get().getRol()).isEqualTo(UsuarioLogin.Rol.ADMINISTRADOR);
        assertThat(resultado.get().getActivo()).isTrue();
    }

    @Test
    public void testBuscarPorCorreo_DebeRetornarVacio_CuandoElCorreoNoExiste() {
        // Act: Buscamos un correo inexistente
        Optional<UsuarioLogin> resultado = repositorioUsuario.buscarPorCorreo("no.existe@impulsaa365.com");

        // Assert: El SP debería retornar un conjunto vacío y JPA resolver un Optional vacío
        assertThat(resultado).isEmpty();
    }

    @Test
    public void testBuscarPorCodigo_DebeRetornarUsuario_CuandoElCodigoExiste() {
        // Arrange: Insertamos otro usuario de prueba
        UsuarioLogin usuario = new UsuarioLogin();
        usuario.setCodigo("EMP888");
        usuario.setCorreo("empleado.test@impulsaa365.com");
        usuario.setClaveHash("$2a$10$abcdefghijklmnopqrstuvwxyz");
        usuario.setRol(UsuarioLogin.Rol.EMPLEADO);
        usuario.setActivo(true);

        entityManager.persist(usuario);
        entityManager.flush();

        // Act: Llamamos al método que ejecuta 'CALL sp_buscar_usuario_por_codigo'
        Optional<UsuarioLogin> resultado = repositorioUsuario.buscarPorCodigo("EMP888");

        // Assert: Verificamos los datos retornados por el SP
        assertThat(resultado).isPresent();
        assertThat(resultado.get().getCorreo()).isEqualTo("empleado.test@impulsaa365.com");
        assertThat(resultado.get().getRol()).isEqualTo(UsuarioLogin.Rol.EMPLEADO);
    }

    @Test
    public void testBuscarPorCodigo_DebeRetornarVacio_CuandoElCodigoNoExiste() {
        // Act
        Optional<UsuarioLogin> resultado = repositorioUsuario.buscarPorCodigo("EMPXYZ");

        // Assert
        assertThat(resultado).isEmpty();
    }
}

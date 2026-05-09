package com.backdea365.app.repository;

import com.backdea365.app.model.UsuarioLogin;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

// Acceso a datos de la tabla usuarios_login via stored procedures de MySQL
@Repository
public interface RepositorioUsuario extends JpaRepository<UsuarioLogin, Integer> {

    // Busca un usuario activo por su correo electronico
    // Llama al stored procedure sp_buscar_usuario_por_correo
    // Se usa en el login con Google y en recuperar contrasena
    @Query(value = "CALL sp_buscar_usuario_por_correo(:correo)", nativeQuery = true)
    Optional<UsuarioLogin> buscarPorCorreo(@Param("correo") String correo);

    // Busca un usuario activo por su codigo de trabajador (ej: EMP001)
    // Llama al stored procedure sp_buscar_usuario_por_codigo
    // Se usa en el login normal y en el filtro JWT
    @Query(value = "CALL sp_buscar_usuario_por_codigo(:codigo)", nativeQuery = true)
    Optional<UsuarioLogin> buscarPorCodigo(@Param("codigo") String codigo);
}

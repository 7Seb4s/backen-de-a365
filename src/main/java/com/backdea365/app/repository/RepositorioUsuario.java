package com.backdea365.app.repository;

// ─────────────────────────────────────────────────────────────
// RepositorioUsuario.java
// Capa de acceso a datos para la tabla 'usuarios_login'.
// Llama directamente a los stored procedures del schema
// impulsa_a365 usando @Query con nativeQuery = true.
// ─────────────────────────────────────────────────────────────

import com.backdea365.app.model.UsuarioLogin;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RepositorioUsuario extends JpaRepository<UsuarioLogin, Integer> {

    // ── Buscar usuario activo por correo ──────────────────────
    // Llama al stored procedure sp_buscar_usuario_por_correo.
    // Se usa en el login cuando el usuario ingresa con su correo.
    @Query(value = "CALL sp_buscar_usuario_por_correo(:correo)", nativeQuery = true)
    Optional<UsuarioLogin> buscarPorCorreo(@Param("correo") String correo);

    // ── Buscar usuario activo por código ──────────────────────
    // Llama al stored procedure sp_buscar_usuario_por_codigo.
    // Se usa en el login cuando el usuario ingresa con su código.
    @Query(value = "CALL sp_buscar_usuario_por_codigo(:codigo)", nativeQuery = true)
    Optional<UsuarioLogin> buscarPorCodigo(@Param("codigo") String codigo);
}

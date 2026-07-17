package com.backdea365.app.repository;

import com.backdea365.app.model.ResetPassword;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

// Acceso a datos de la tabla reset_password
@Repository
public interface RepositorioResetPassword extends JpaRepository<ResetPassword, Integer> {

    // Busca el codigo mas reciente que todavia sea valido para un correo
    // Un codigo es valido si: no fue usado y no ha expirado
    @Query("""
        SELECT r FROM ResetPassword r
        WHERE r.correo = :correo
          AND r.usado = false
          AND r.expiracion > :ahora
        ORDER BY r.creadoEn DESC
        LIMIT 1
    """)
    Optional<ResetPassword> buscarCodigoVigente(
        @Param("correo") String correo,
        @Param("ahora")  LocalDateTime ahora
    );

    // Marca como usados todos los codigos anteriores de un correo
    // Se llama antes de generar uno nuevo para evitar codigos duplicados activos
    @Modifying
    @Transactional
    @Query("UPDATE ResetPassword r SET r.usado = true WHERE r.correo = :correo")
    void invalidarCodigos(@Param("correo") String correo);

    // Borra los codigos que ya no sirven: expirados o ya usados.
    // Lo usa la tarea programada de limpieza. Devuelve cuantas filas borro.
    @Modifying
    @Transactional
    @Query("DELETE FROM ResetPassword r WHERE r.expiracion < :ahora OR r.usado = true")
    int borrarExpiradosYUsados(@Param("ahora") LocalDateTime ahora);
}

package com.backdea365.app.tarea;

import com.backdea365.app.repository.RepositorioResetPassword;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

/**
 * Tarea programada (cron job) que mantiene limpia la tabla reset_password.
 *
 * Cada hora borra los codigos de recuperacion de contrasena que ya expiraron
 * o que ya fueron usados, para que la tabla no crezca indefinidamente con
 * datos que ya no sirven.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class TareaLimpiezaTokens {

    private final RepositorioResetPassword repositorioResetPassword;

    // Expresion cron: segundo minuto hora diaMes mes diaSemana
    // "0 0 * * * *" = al minuto 0 de cada hora (01:00, 02:00, 03:00, ...)
    @Scheduled(cron = "0 0 * * * *")
    public void limpiarTokensExpirados() {
        int borrados = repositorioResetPassword.borrarExpiradosYUsados(LocalDateTime.now());

        if (borrados > 0) {
            log.info("Limpieza de tokens: se borraron {} codigos de recuperacion expirados o usados", borrados);
        } else {
            log.debug("Limpieza de tokens: no habia codigos para borrar");
        }
    }
}

package com.backdea365.app.controller;

import com.backdea365.app.dto.RecuperarDTO;
import com.backdea365.app.service.ServicioRecuperacion;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

// Maneja los 3 pasos del flujo de recuperacion de contrasena
@RestController
@RequestMapping("/api/auth/recuperar")
@RequiredArgsConstructor
public class ControladorRecuperacion {

    private final ServicioRecuperacion servicioRecuperacion;

    // POST /api/auth/recuperar/solicitar
    // Recibe el correo, genera un codigo de 6 digitos y lo envia por email via Resend
    @PostMapping("/solicitar")
    public ResponseEntity<Void> solicitar(
            @Valid @RequestBody RecuperarDTO.SolicitarRequest req
    ) {
        servicioRecuperacion.solicitarCodigo(req);
        return ResponseEntity.ok().build();
    }

    // POST /api/auth/recuperar/verificar
    // Recibe correo + codigo y verifica que sea correcto y no haya expirado
    @PostMapping("/verificar")
    public ResponseEntity<Void> verificar(
            @Valid @RequestBody RecuperarDTO.VerificarRequest req
    ) {
        servicioRecuperacion.verificarCodigo(req);
        return ResponseEntity.ok().build();
    }

    // POST /api/auth/recuperar/cambiar
    // Recibe correo + codigo + nueva contrasena, verifica el codigo y actualiza la BD
    @PostMapping("/cambiar")
    public ResponseEntity<Void> cambiar(
            @Valid @RequestBody RecuperarDTO.CambiarRequest req
    ) {
        servicioRecuperacion.cambiarPassword(req);
        return ResponseEntity.ok().build();
    }
}

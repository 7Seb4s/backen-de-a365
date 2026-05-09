package com.backdea365.app.controller;

import com.backdea365.app.dto.AuthDTO;
import com.backdea365.app.dto.GoogleAuthDTO;
import com.backdea365.app.service.ServicioGoogleAuth;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

// Recibe el token de Google del frontend y devuelve un JWT propio del sistema
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class ControladorGoogleAuth {

    private final ServicioGoogleAuth servicioGoogleAuth;

    // POST /api/auth/google
    // Recibe el credential de Google, valida que el correo este registrado
    // y devuelve el mismo JWT que el login normal
    @PostMapping("/google")
    public ResponseEntity<AuthDTO.LoginResponse> loginConGoogle(
            @Valid @RequestBody GoogleAuthDTO.GoogleLoginRequest peticion
    ) {
        AuthDTO.LoginResponse respuesta = servicioGoogleAuth.loginConGoogle(peticion.getCredential());
        return ResponseEntity.ok(respuesta);
    }
}

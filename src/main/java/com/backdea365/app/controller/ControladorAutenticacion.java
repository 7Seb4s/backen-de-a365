package com.backdea365.app.controller;

// -------------------------------------------------------------
// ControladorAutenticacion.java
// Expone el endpoint de login del sistema.
// Recibe el codigo y contrasena del usuario, delega al servicio
// para verificar las credenciales y devuelve el token JWT.
// -------------------------------------------------------------

import com.backdea365.app.dto.AuthDTO;
import com.backdea365.app.service.ServicioAutenticacion;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class ControladorAutenticacion {

    private final ServicioAutenticacion servicioAuth;

    // -- POST /api/auth/login --------------------------------------
    // Recibe codigo + password en el body.
    // Si las credenciales son correctas retorna el token JWT y datos del usuario.
    // Si son incorrectas Spring Security lanza una excepcion y responde 401.
    @PostMapping("/login")
    public ResponseEntity<AuthDTO.LoginResponse> login(
            @Valid @RequestBody AuthDTO.LoginRequest peticion
    ) {
        AuthDTO.LoginResponse respuesta = servicioAuth.login(peticion);
        return ResponseEntity.ok(respuesta);
    }
}

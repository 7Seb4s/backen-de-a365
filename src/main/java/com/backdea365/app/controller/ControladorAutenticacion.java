package com.backdea365.app.controller;

import com.backdea365.app.dto.AuthDTO;
import com.backdea365.app.service.ServicioAutenticacion;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

// Recibe las peticiones de login y las delega al servicio de autenticacion
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class ControladorAutenticacion {

    private final ServicioAutenticacion servicioAuth;

    // POST /api/auth/login
    // Recibe codigo + contrasena, devuelve token JWT si las credenciales son correctas
    @PostMapping("/login")
    public ResponseEntity<AuthDTO.LoginResponse> login(
            @Valid @RequestBody AuthDTO.LoginRequest peticion
    ) {
        AuthDTO.LoginResponse respuesta = servicioAuth.login(peticion);
        return ResponseEntity.ok(respuesta);
    }
}

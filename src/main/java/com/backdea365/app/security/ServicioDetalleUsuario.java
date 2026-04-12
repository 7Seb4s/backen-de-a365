package com.backdea365.app.security;

// ─────────────────────────────────────────────────────────────
// ServicioDetalleUsuario.java
// Implementa UserDetailsService de Spring Security.
// Su único trabajo es cargar un usuario desde la base de datos
// dado su código, para que Spring Security pueda autenticarlo.
// ─────────────────────────────────────────────────────────────

import com.backdea365.app.model.UsuarioLogin;
import com.backdea365.app.repository.RepositorioUsuario;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class ServicioDetalleUsuario implements UserDetailsService {

    private final RepositorioUsuario repositorioUsuario;

    // ── CARGAR USUARIO POR CÓDIGO ─────────────────────────────
    // Spring Security llama a este método cuando necesita verificar
    // quién es el usuario que viene en el token JWT.
    // Busca en la tabla usuarios_login usando el stored procedure
    // sp_buscar_usuario_por_codigo.
    @Override
    public UserDetails loadUserByUsername(String codigo) throws UsernameNotFoundException {

        // Buscar el usuario activo en la base de datos
        UsuarioLogin usuario = repositorioUsuario.buscarPorCodigo(codigo)
                .orElseThrow(() -> new UsernameNotFoundException(
                        "Usuario no encontrado con código: " + codigo
                ));

        // Convertir el rol al formato que espera Spring Security (ROLE_EMPLEADO, etc.)
        String rol = "ROLE_" + usuario.getRol().name();

        // Retornar el objeto UserDetails que Spring Security necesita
        return new User(
                usuario.getCodigo(),
                usuario.getClaveHash(),
                List.of(new SimpleGrantedAuthority(rol))
        );
    }
}

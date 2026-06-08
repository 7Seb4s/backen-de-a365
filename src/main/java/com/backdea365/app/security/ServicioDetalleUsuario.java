package com.backdea365.app.security;

import com.backdea365.app.model.UsuarioLogin;
import com.backdea365.app.repository.RepositorioUsuario;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

// Carga los datos del usuario desde la BD para que Spring Security pueda autenticarlo
// Spring Security llama a este servicio cuando recibe un token JWT valido
@Service
@RequiredArgsConstructor
public class ServicioDetalleUsuario implements UserDetailsService {

    private final RepositorioUsuario repositorioUsuario;

    // Busca el usuario por su codigo de trabajador y devuelve sus datos a Spring Security
    // Llama al stored procedure sp_buscar_usuario_por_codigo
    @Override
    public UserDetails loadUserByUsername(String codigo) throws UsernameNotFoundException {

        // Buscar el usuario activo en la BD
        UsuarioLogin usuario = repositorioUsuario.buscarPorCodigo(codigo)
                .orElseThrow(() -> new UsernameNotFoundException(
                        "Usuario no encontrado con codigo: " + codigo
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

    // Helper usado por los controladores para resolver el ID numerico del usuario
    // a partir del codigo que viene en el token JWT (subject)
    public Integer obtenerIdPorCodigo(String codigo) {
        return repositorioUsuario.buscarPorCodigo(codigo)
                .map(UsuarioLogin::getIdUsuario)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED, "Usuario no encontrado"
                ));
    }
}

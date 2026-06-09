package com.backdea365.app.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.nio.file.Paths;

// Expone la carpeta de fotos subidas como recurso estático accesible vía HTTP
// Las fotos se sirven en: GET /uploads/fotos/{nombreArchivo}
// Solo usuarios autenticados pueden acceder (el filtro JWT protege todo por defecto)
@Configuration
public class ConfiguracionRecursos implements WebMvcConfigurer {

    @Value("${app.upload.dir:uploads/fotos}")
    private String uploadDir;

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        // Convierte la ruta relativa a una ruta absoluta con prefijo file:
        String rutaAbsoluta = Paths.get(uploadDir).toAbsolutePath().toString();

        registry.addResourceHandler("/uploads/fotos/**")
                .addResourceLocations("file:" + rutaAbsoluta + "/");
    }
}

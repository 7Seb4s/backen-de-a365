package com.backdea365.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

// Clase principal que arranca toda la aplicacion Spring Boot
// @EnableScheduling activa las tareas programadas (cron jobs) con @Scheduled
@SpringBootApplication
@EnableScheduling
public class BackDeA365Application {

    public static void main(String[] args) {
        // Inicia el servidor en el puerto definido en application.properties (8081)
        SpringApplication.run(BackDeA365Application.class, args);
    }
}

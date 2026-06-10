package com.backdea365.app.controller;

import com.backdea365.app.service.ServicioExportacion;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

// Endpoints para exportar datos a Excel (.xlsx)
// Usa Apache POI a través de ServicioExportacion
// Solo accesible para ADMINISTRADOR y GERENTE
@RestController
@RequestMapping("/api/exportar")
@RequiredArgsConstructor
@PreAuthorize("hasAnyRole('ADMINISTRADOR', 'GERENTE')")
public class ControladorExportacion {

    private final ServicioExportacion servicioExportacion;

    // GET /api/exportar/usuarios-activos
    // Descarga un archivo Excel con la lista de usuarios activos
    @GetMapping("/usuarios-activos")
    public ResponseEntity<byte[]> exportarUsuariosActivos() throws IOException {
        byte[] excel = servicioExportacion.exportarUsuariosActivos();
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=usuarios_activos.xlsx")
                .contentType(MediaType.parseMediaType(
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"))
                .body(excel);
    }

    // GET /api/exportar/usuarios-eliminados
    // Descarga un archivo Excel con el historial de usuarios eliminados
    @GetMapping("/usuarios-eliminados")
    public ResponseEntity<byte[]> exportarUsuariosEliminados() throws IOException {
        byte[] excel = servicioExportacion.exportarUsuariosEliminados();
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=usuarios_eliminados.xlsx")
                .contentType(MediaType.parseMediaType(
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"))
                .body(excel);
    }

    // ── PDF ──

    // GET /api/exportar/usuarios-activos-pdf
    // Descarga un archivo PDF con la lista de usuarios activos
    @GetMapping("/usuarios-activos-pdf")
    public ResponseEntity<byte[]> exportarUsuariosActivosPdf() throws Exception {
        byte[] pdf = servicioExportacion.exportarUsuariosActivosPdf();
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=usuarios_activos.pdf")
                .contentType(MediaType.APPLICATION_PDF)
                .body(pdf);
    }

    // GET /api/exportar/usuarios-eliminados-pdf
    // Descarga un archivo PDF con el historial de usuarios eliminados
    @GetMapping("/usuarios-eliminados-pdf")
    public ResponseEntity<byte[]> exportarUsuariosEliminadosPdf() throws Exception {
        byte[] pdf = servicioExportacion.exportarUsuariosEliminadosPdf();
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=usuarios_eliminados.pdf")
                .contentType(MediaType.APPLICATION_PDF)
                .body(pdf);
    }
}

package com.backdea365.app.service;

import com.backdea365.app.dto.UsuarioDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.ss.util.CellRangeAddress;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

// Servicio de exportación de datos a Excel (.xlsx)
// Usa Apache POI para generar los archivos y Apache Commons para validaciones
@Slf4j
@Service
@RequiredArgsConstructor
public class ServicioExportacion {

    private final ServicioUsuario servicioUsuario;

    // Colores corporativos A365
    private static final short COLOR_HEADER = IndexedColors.DARK_BLUE.getIndex();
    private static final short COLOR_BLANCO = IndexedColors.WHITE.getIndex();

    // ── Exportar lista de usuarios activos a Excel ──
    // Genera un archivo .xlsx con encabezados estilizados y datos formateados
    public byte[] exportarUsuariosActivos() throws IOException {
        List<UsuarioDTO.PanelItem> usuarios = servicioUsuario.listarActivos();
        return generarExcelUsuarios(usuarios, "Usuarios Activos");
    }

    // ── Exportar lista de usuarios eliminados a Excel ──
    public byte[] exportarUsuariosEliminados() throws IOException {
        List<UsuarioDTO.PanelItem> usuarios = servicioUsuario.listarEliminados();
        return generarExcelUsuarios(usuarios, "Usuarios Eliminados");
    }

    // ── Generador principal del Excel de usuarios ──
    // Apache POI: crea workbook, sheet, estilos y filas
    private byte[] generarExcelUsuarios(
            List<UsuarioDTO.PanelItem> usuarios, String titulo) throws IOException {

        try (Workbook workbook = new XSSFWorkbook()) {

            Sheet sheet = workbook.createSheet(titulo);

            // ── Estilos ──
            CellStyle estiloTitulo = crearEstiloTitulo(workbook);
            CellStyle estiloHeader = crearEstiloHeader(workbook);
            CellStyle estiloDato   = crearEstiloDato(workbook);

            int filaActual = 0;

            // ── Fila 0: Título del reporte ──
            Row filaTitulo = sheet.createRow(filaActual++);
            Cell celdaTitulo = filaTitulo.createCell(0);
            celdaTitulo.setCellValue("Reporte: " + titulo + " — Impulsa A365");
            celdaTitulo.setCellStyle(estiloTitulo);
            sheet.addMergedRegion(new CellRangeAddress(0, 0, 0, 5));

            // ── Fila 1: Fecha de generación ──
            Row filaFecha = sheet.createRow(filaActual++);
            Cell celdaFecha = filaFecha.createCell(0);
            String fechaGeneracion = LocalDateTime.now()
                    .format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss"));
            celdaFecha.setCellValue("Generado: " + fechaGeneracion);

            filaActual++; // fila vacía de separación

            // ── Fila 3: Encabezados de columnas ──
            String[] columnas = {"#", "Código", "Nombre Completo", "DNI", "Correo", "Cargo"};
            Row filaHeader = sheet.createRow(filaActual++);
            for (int i = 0; i < columnas.length; i++) {
                Cell celda = filaHeader.createCell(i);
                celda.setCellValue(columnas[i]);
                celda.setCellStyle(estiloHeader);
            }

            // ── Filas de datos ──
            // Apache Commons: CollectionUtils para validar lista vacía
            if (CollectionUtils.isNotEmpty(usuarios)) {
                int numero = 1;
                for (UsuarioDTO.PanelItem u : usuarios) {
                    Row fila = sheet.createRow(filaActual++);

                    crearCelda(fila, 0, String.valueOf(numero++), estiloDato);
                    // Apache Commons: defaultIfBlank para manejar nulos
                    crearCelda(fila, 1, StringUtils.defaultIfBlank(u.getCodigo(), "—"), estiloDato);
                    crearCelda(fila, 2, StringUtils.defaultIfBlank(u.getNombre(), "—"), estiloDato);
                    crearCelda(fila, 3, StringUtils.defaultIfBlank(u.getDni(), "—"), estiloDato);
                    crearCelda(fila, 4, StringUtils.defaultIfBlank(u.getCorreo(), "—"), estiloDato);
                    crearCelda(fila, 5, StringUtils.defaultIfBlank(u.getCargo(), "—"), estiloDato);
                }
            } else {
                Row fila = sheet.createRow(filaActual);
                fila.createCell(0).setCellValue("No se encontraron usuarios.");
            }

            // Auto-ajustar ancho de columnas
            for (int i = 0; i < columnas.length; i++) {
                sheet.autoSizeColumn(i);
            }

            // Convertir a bytes para enviar como descarga
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            workbook.write(outputStream);

            log.info("Excel de {} generado: {} registros", titulo, usuarios.size());
            return outputStream.toByteArray();
        }
    }

    // ── Helpers de estilo (Apache POI) ──

    private CellStyle crearEstiloTitulo(Workbook wb) {
        CellStyle estilo = wb.createCellStyle();
        Font font = wb.createFont();
        font.setBold(true);
        font.setFontHeightInPoints((short) 14);
        font.setColor(COLOR_HEADER);
        estilo.setFont(font);
        return estilo;
    }

    private CellStyle crearEstiloHeader(Workbook wb) {
        CellStyle estilo = wb.createCellStyle();
        Font font = wb.createFont();
        font.setBold(true);
        font.setColor(COLOR_BLANCO);
        font.setFontHeightInPoints((short) 11);
        estilo.setFont(font);
        estilo.setFillForegroundColor(COLOR_HEADER);
        estilo.setFillPattern(FillPatternType.SOLID_FOREGROUND);
        estilo.setBorderBottom(BorderStyle.THIN);
        estilo.setAlignment(HorizontalAlignment.CENTER);
        return estilo;
    }

    private CellStyle crearEstiloDato(Workbook wb) {
        CellStyle estilo = wb.createCellStyle();
        estilo.setBorderBottom(BorderStyle.THIN);
        estilo.setBorderTop(BorderStyle.THIN);
        estilo.setBorderLeft(BorderStyle.THIN);
        estilo.setBorderRight(BorderStyle.THIN);
        estilo.setVerticalAlignment(VerticalAlignment.CENTER);
        return estilo;
    }

    private void crearCelda(Row fila, int columna, String valor, CellStyle estilo) {
        Cell celda = fila.createCell(columna);
        celda.setCellValue(valor);
        celda.setCellStyle(estilo);
    }
}

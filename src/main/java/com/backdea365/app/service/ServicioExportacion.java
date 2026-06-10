package com.backdea365.app.service;

import com.backdea365.app.dto.UsuarioDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.ss.util.CellRangeAddress;
import org.apache.poi.util.IOUtils;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

// Servicio de exportación de datos a Excel (.xlsx) y PDF
// Usa Apache POI para Excel, iTextPDF para PDF, y Apache Commons para validaciones
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

            // ── Logo de la empresa (Apache POI: insertar imagen) ──
            try {
                InputStream logoStream = new ClassPathResource("logo-a365.jpg").getInputStream();
                byte[] logoBytes = IOUtils.toByteArray(logoStream);
                int logoIdx = workbook.addPicture(logoBytes, Workbook.PICTURE_TYPE_JPEG);
                logoStream.close();

                CreationHelper helper = workbook.getCreationHelper();
                Drawing<?> drawing = sheet.createDrawingPatriarch();
                ClientAnchor anchor = helper.createClientAnchor();
                anchor.setCol1(0);
                anchor.setRow1(0);
                anchor.setCol2(2);
                anchor.setRow2(3);
                drawing.createPicture(anchor, logoIdx);
                filaActual = 3; // saltar las filas del logo
            } catch (Exception e) {
                log.warn("No se pudo cargar el logo para Excel: {}", e.getMessage());
            }

            // ── Título del reporte ──
            Row filaTitulo = sheet.createRow(filaActual++);
            Cell celdaTitulo = filaTitulo.createCell(0);
            celdaTitulo.setCellValue("Reporte: " + titulo + " — Impulsa A365");
            celdaTitulo.setCellStyle(estiloTitulo);
            sheet.addMergedRegion(new CellRangeAddress(filaActual - 1, filaActual - 1, 0, 5));

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

    // ═══════════════════════════════════════════════════
    //  EXPORTACIÓN A PDF (iTextPDF)
    // ═══════════════════════════════════════════════════

    // ── Exportar usuarios activos a PDF ──
    public byte[] exportarUsuariosActivosPdf() throws Exception {
        return generarPdfUsuarios(servicioUsuario.listarActivos(), "Usuarios Activos");
    }

    // ── Exportar usuarios eliminados a PDF ──
    public byte[] exportarUsuariosEliminadosPdf() throws Exception {
        return generarPdfUsuarios(servicioUsuario.listarEliminados(), "Usuarios Eliminados");
    }

    // ── Generador principal del PDF ──
    // iTextPDF: crea documento, tabla con encabezados estilizados y datos
    private byte[] generarPdfUsuarios(
            List<UsuarioDTO.PanelItem> usuarios, String titulo) throws Exception {

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        com.itextpdf.text.Document documento = new com.itextpdf.text.Document(
                com.itextpdf.text.PageSize.A4.rotate()  // Horizontal para más columnas
        );
        com.itextpdf.text.pdf.PdfWriter.getInstance(documento, out);
        documento.open();

        // ── Logo (iTextPDF: insertar imagen) ──
        try {
            InputStream logoStream = new ClassPathResource("logo-a365.jpg").getInputStream();
            byte[] logoBytes = logoStream.readAllBytes();
            logoStream.close();
            com.itextpdf.text.Image logo = com.itextpdf.text.Image.getInstance(logoBytes);
            logo.scaleToFit(120, 60);
            logo.setSpacingAfter(10);
            documento.add(logo);
        } catch (Exception e) {
            log.warn("No se pudo cargar el logo para PDF: {}", e.getMessage());
        }

        // ── Fuentes ──
        com.itextpdf.text.Font fuenteTitulo = new com.itextpdf.text.Font(
                com.itextpdf.text.Font.FontFamily.HELVETICA, 16,
                com.itextpdf.text.Font.BOLD, new com.itextpdf.text.BaseColor(27, 37, 89)
        );
        com.itextpdf.text.Font fuenteHeader = new com.itextpdf.text.Font(
                com.itextpdf.text.Font.FontFamily.HELVETICA, 10,
                com.itextpdf.text.Font.BOLD, com.itextpdf.text.BaseColor.WHITE
        );
        com.itextpdf.text.Font fuenteDato = new com.itextpdf.text.Font(
                com.itextpdf.text.Font.FontFamily.HELVETICA, 9,
                com.itextpdf.text.Font.NORMAL, com.itextpdf.text.BaseColor.DARK_GRAY
        );
        com.itextpdf.text.Font fuenteFecha = new com.itextpdf.text.Font(
                com.itextpdf.text.Font.FontFamily.HELVETICA, 8,
                com.itextpdf.text.Font.NORMAL, com.itextpdf.text.BaseColor.GRAY
        );

        // ── Título ──
        com.itextpdf.text.Paragraph paraTitulo = new com.itextpdf.text.Paragraph(
                "Reporte: " + titulo + " — Impulsa A365", fuenteTitulo
        );
        paraTitulo.setSpacingAfter(4);
        documento.add(paraTitulo);

        // ── Fecha de generación ──
        String fecha = java.time.LocalDateTime.now()
                .format(java.time.format.DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss"));
        com.itextpdf.text.Paragraph paraFecha = new com.itextpdf.text.Paragraph(
                "Generado: " + fecha, fuenteFecha
        );
        paraFecha.setSpacingAfter(14);
        documento.add(paraFecha);

        // ── Tabla ──
        String[] columnas = {"#", "Codigo", "Nombre Completo", "DNI", "Correo", "Cargo"};
        com.itextpdf.text.pdf.PdfPTable tabla = new com.itextpdf.text.pdf.PdfPTable(columnas.length);
        tabla.setWidthPercentage(100);
        tabla.setWidths(new float[]{5, 10, 25, 12, 28, 15});

        // Headers con fondo azul oscuro
        com.itextpdf.text.BaseColor colorHeader = new com.itextpdf.text.BaseColor(27, 37, 89);
        for (String col : columnas) {
            com.itextpdf.text.pdf.PdfPCell celda = new com.itextpdf.text.pdf.PdfPCell(
                    new com.itextpdf.text.Phrase(col, fuenteHeader)
            );
            celda.setBackgroundColor(colorHeader);
            celda.setPadding(6);
            celda.setHorizontalAlignment(com.itextpdf.text.Element.ALIGN_CENTER);
            tabla.addCell(celda);
        }

        // Filas de datos
        if (CollectionUtils.isNotEmpty(usuarios)) {
            int numero = 1;
            for (UsuarioDTO.PanelItem u : usuarios) {
                tabla.addCell(new com.itextpdf.text.Phrase(String.valueOf(numero++), fuenteDato));
                tabla.addCell(new com.itextpdf.text.Phrase(StringUtils.defaultIfBlank(u.getCodigo(), "—"), fuenteDato));
                tabla.addCell(new com.itextpdf.text.Phrase(StringUtils.defaultIfBlank(u.getNombre(), "—"), fuenteDato));
                tabla.addCell(new com.itextpdf.text.Phrase(StringUtils.defaultIfBlank(u.getDni(), "—"), fuenteDato));
                tabla.addCell(new com.itextpdf.text.Phrase(StringUtils.defaultIfBlank(u.getCorreo(), "—"), fuenteDato));
                tabla.addCell(new com.itextpdf.text.Phrase(StringUtils.defaultIfBlank(u.getCargo(), "—"), fuenteDato));
            }
        }

        documento.add(tabla);
        documento.close();

        log.info("PDF de {} generado: {} registros", titulo, usuarios.size());
        return out.toByteArray();
    }
}

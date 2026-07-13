package com.backdea365.app.service;

import com.backdea365.app.dto.ReniecDTO;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

// Consulta datos personales por DNI contra la API de Decolecta (RENIEC).
// Se usa al crear un usuario para autocompletar nombres y apellidos.
@Slf4j
@Service
public class ServicioReniec {

    private final RestTemplate rest;

    public ServicioReniec() {
        // Timeouts para no colgar la peticion si Decolecta no responde
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(5000);
        factory.setReadTimeout(8000);
        this.rest = new RestTemplate(factory);
    }

    // URL base y token leidos de application.properties
    @Value("${decolecta.base-url:https://api.decolecta.com}")
    private String baseUrl;

    @Value("${decolecta.api-key}")
    private String apiKey;

    // Consulta el DNI y devuelve los nombres/apellidos ya mapeados
    public ReniecDTO.Persona consultarDni(String dni) {
        String numero = StringUtils.trimToEmpty(dni);
        if (!numero.matches("\\d{8}")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "El DNI debe tener exactamente 8 dígitos");
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(apiKey);
            headers.setAccept(List.of(MediaType.APPLICATION_JSON));
            HttpEntity<Void> peticion = new HttpEntity<>(headers);

            ResponseEntity<ReniecDTO.ApiResponse> respuesta = rest.exchange(
                    baseUrl + "/v1/reniec/dni?numero=" + numero,
                    HttpMethod.GET,
                    peticion,
                    ReniecDTO.ApiResponse.class
            );

            ReniecDTO.ApiResponse cuerpo = respuesta.getBody();
            if (cuerpo == null || StringUtils.isBlank(cuerpo.getDocumentNumber())) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "No se encontraron datos para el DNI " + numero);
            }
            return mapear(cuerpo, numero);

        } catch (HttpClientErrorException.NotFound e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                    "No se encontraron datos para el DNI " + numero);
        } catch (HttpClientErrorException.Unauthorized | HttpClientErrorException.Forbidden e) {
            log.error("Token de Decolecta invalido o sin permisos: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY,
                    "Error de autenticación con el servicio de RENIEC");
        } catch (ResponseStatusException e) {
            throw e;
        } catch (Throwable e) {
            log.error("Error consultando RENIEC para DNI {}", numero, e);
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY,
                    "No se pudo consultar el servicio de RENIEC. Intenta de nuevo.");
        }
    }

    // Convierte la respuesta cruda de la API en el DTO que consume el frontend
    private ReniecDTO.Persona mapear(ReniecDTO.ApiResponse api, String dni) {
        String apellidos = StringUtils.normalizeSpace(
                StringUtils.trimToEmpty(api.getFirstLastName()) + " " +
                StringUtils.trimToEmpty(api.getSecondLastName())
        );
        return new ReniecDTO.Persona(
                dni,
                StringUtils.trimToEmpty(api.getFirstName()),
                StringUtils.trimToEmpty(api.getFirstLastName()),
                StringUtils.trimToEmpty(api.getSecondLastName()),
                apellidos,
                api.getFullName()
        );
    }
}

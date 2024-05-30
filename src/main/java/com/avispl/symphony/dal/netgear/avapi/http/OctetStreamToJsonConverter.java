/*
 * Copyright (c) 2024 AVI-SPL, Inc. All Rights Reserved.
 */
package com.avispl.symphony.dal.netgear.avapi.http;

import com.avispl.symphony.dal.aggregator.parser.AggregatedDeviceProcessor;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Octet stream to json converter, made to support API responses that do not have Content-Type headers provided
 *
 * @author Maksym.Rossiitsev/AVISPL Team
 * */
public class OctetStreamToJsonConverter extends AbstractHttpMessageConverter<Object> {
    /**
     * Device data processor provided by main communicator, that instantiates the converter
     * */
    private final AggregatedDeviceProcessor deviceDataProcessor;
    /**
     * Object mapper to transform the plaintext body to a json response
     * */
    private final ObjectMapper objectMapper;
    /**
     * Class logger to log various events
     * */
    private final Log logger = LogFactory.getLog(this.getClass());

    public OctetStreamToJsonConverter(AggregatedDeviceProcessor deviceDataProcessor) {
        super(MediaType.APPLICATION_OCTET_STREAM);
        this.objectMapper = new ObjectMapper();

        this.deviceDataProcessor = deviceDataProcessor;
    }

    @Override
    protected boolean supports(Class<?> clazz) {
        // We'll parse any class as JSON for simplicity
        return true;
    }

    @Override
    protected Object readInternal(Class<? extends Object> clazz, HttpInputMessage inputMessage)
            throws IOException, HttpMessageNotReadableException {
        JsonNode jsonResponse = objectMapper.readTree(inputMessage.getBody());
        Map<String, String> responseProperties = new HashMap<>();
        deviceDataProcessor.applyProperties(responseProperties, jsonResponse, "NetgearBase");

        String responseStatus = responseProperties.get("ResponseStatus");
        String responseCode = responseProperties.get("ResponseCode");
        String responseMessage = responseProperties.get("ResponseMessage");
        if (responseStatus.equals("fail")) {
            throw new RuntimeException(String.format("Failed to process the request: Code: %s, Message: %s", responseCode, responseMessage));
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug(String.format("Successful response process: Code: %s, Message: %s", responseCode, responseMessage));
            }
        }
        return jsonResponse;
    }

    @Override
    protected void writeInternal(Object t, HttpOutputMessage outputMessage)
            throws HttpMessageNotWritableException {
        // Serialization logic if needed
    }
}

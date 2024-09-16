/*
 * Copyright (c) 2024 AVI-SPL, Inc. All Rights Reserved.
 */
package com.avispl.symphony.dal.netgear.avapi.data;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

/**
 * Ping mode - ICMP vs TCP
 * @author Maksym Rossiitsev
 * @since 1.0.0
 */
public enum PingMode {
    ICMP("ICMP"), TCP("TCP");
    private static final Log logger = LogFactory.getLog(PingMode.class);

    private String mode;

    PingMode(String mode) {
        this.mode = mode;
    }

    /**
     * Retrieve PingMode instance based on string value of mode - TCP or ICMP
     *
     * @param mode string value of pingMode
     * @response PingMode instance, based on the string value
     * */
    public static PingMode ofString(String mode) {
        if (logger.isDebugEnabled()) {
            logger.debug("Requested PING mode: " + mode);
        }
        Optional<PingMode> selectedPingMode = Arrays.stream(PingMode.values()).filter(authorizationMode -> Objects.equals(mode, authorizationMode.mode)).findFirst();
        return selectedPingMode.orElse(PingMode.ICMP);
    }
}

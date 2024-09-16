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
 * Monitoring mode - Unit vs Stack
 * @author Maksym Rossiitsev
 * @since 1.0.0
 */
public enum MonitoringMode {
    UNIT("Unit"), STACK("Stack");
    private static final Log logger = LogFactory.getLog(PingMode.class);

    private String mode;

    MonitoringMode(String mode) {
        this.mode = mode;
    }

    /**
     * Retrieve MonitoringMode instance based on string value of mode - Unit or Stack
     *
     * @param mode string value of mode
     * @response MonitoringMode instance, based on the mode value
     * */
    public static MonitoringMode ofString(String mode) {
        if (logger.isDebugEnabled()) {
            logger.debug("Requested Monitoring Mode: " + mode);
        }
        Optional<MonitoringMode> selectedAuthMode = Arrays.stream(MonitoringMode.values()).filter(monitoringMode -> Objects.equals(mode, monitoringMode.mode)).findFirst();
        return selectedAuthMode.orElse(MonitoringMode.STACK);
    }
}

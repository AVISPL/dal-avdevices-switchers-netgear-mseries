/*
 * Copyright (c) 2024 AVI-SPL, Inc. All Rights Reserved.
 */
package com.avispl.symphony.dal.netgear.avapi.utils;

import com.avispl.symphony.dal.util.StringUtils;

import java.util.Collection;
import java.util.ServiceConfigurationError;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility class that contains various usable functions
 *
 * @author Maksym.Rossiitsev/AVISPL Team
 * */
public class Utils {
    /**
     * Extract number from string
     *
     * @param str String value that contains number
     * @return Long value exctracted from the string
     * */
    public static Long extractNumber(String str) {
        String pattern = "\\d+";
        Pattern compiledPattern = Pattern.compile(pattern);
        Matcher matcher = compiledPattern.matcher(str);
        if (matcher.find()) {
            return Long.parseLong(matcher.group());
        }
        return 0L;
    }

    /**
     * Resolve serial number of the unit to monitor in Unit monitoring mode.
     * The configured serial number is used if present in the stack, otherwise the only stack unit is used,
     * if there is exactly one.
     *
     * @param configuredSerialNumber configured managementUnitSerialNumber value, may be null or empty
     * @param stackUnitSerialNumbers serial numbers of the units currently retrieved from the stack
     * @return serial number of the unit to monitor
     * @throws ServiceConfigurationError if the configured serial number is not in the stack,
     * or if it is not configured and the stack has more than one unit
     * @throws IllegalStateException if it is not configured and no stack units were retrieved
     * */
    public static String resolveManagementUnitSerialNumber(String configuredSerialNumber, Collection<String> stackUnitSerialNumbers) {
        if (StringUtils.isNotNullOrEmpty(configuredSerialNumber)) {
            if (!stackUnitSerialNumbers.contains(configuredSerialNumber)) {
                throw new ServiceConfigurationError(String.format("Management unit serial number (managementUnitSerialNumber) %s is not found in the stack, available units: %s. Please check adapter configuration.", configuredSerialNumber, stackUnitSerialNumbers));
            }
            return configuredSerialNumber;
        }
        if (stackUnitSerialNumbers.isEmpty()) {
            throw new IllegalStateException("Unable to resolve management unit: no stack units were retrieved from the device.");
        }
        if (stackUnitSerialNumbers.size() > 1) {
            throw new ServiceConfigurationError("Management unit serial number (managementUnitSerialNumber) is not configured, ambiguous monitoring settings. Please check adapter configuration.");
        }
        return stackUnitSerialNumbers.iterator().next();
    }
}

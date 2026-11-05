/*
 * Copyright (c) 2024 AVI-SPL, Inc. All Rights Reserved.
 */
package com.avispl.symphony.dal.netgear.avapi.utils;

import com.avispl.symphony.dal.util.StringUtils;

import java.util.Map;
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
     * The configured serial number is used if present in the stack, otherwise the default unit is used
     * (see {@link #defaultManagementUnitSerialNumber(Map)}).
     *
     * @param configuredSerialNumber configured managementUnitSerialNumber value, may be null or empty
     * @param serialNumberToUnitNumber serial number to unit number of the units currently retrieved from the stack
     * @return serial number of the unit to monitor
     * @throws ServiceConfigurationError if the configured serial number is not in the stack
     * @throws IllegalStateException if it is not configured and no stack units were retrieved
     * */
    public static String resolveManagementUnitSerialNumber(String configuredSerialNumber, Map<String, String> serialNumberToUnitNumber) {
        if (StringUtils.isNotNullOrEmpty(configuredSerialNumber)) {
            if (!serialNumberToUnitNumber.containsKey(configuredSerialNumber)) {
                throw new ServiceConfigurationError(String.format("Management unit serial number (managementUnitSerialNumber) %s is not found in the stack, available units: %s. Please check adapter configuration.", configuredSerialNumber, serialNumberToUnitNumber.keySet()));
            }
            return configuredSerialNumber;
        }
        String defaultSerialNumber = defaultManagementUnitSerialNumber(serialNumberToUnitNumber);
        if (defaultSerialNumber == null) {
            throw new IllegalStateException("Unable to resolve management unit: no stack units were retrieved from the device.");
        }
        return defaultSerialNumber;
    }

    /**
     * Serial number of the unit used when managementUnitSerialNumber is not configured: the unit with unit number 1,
     * or, if the stack has no unit 1, the unit with the lowest unit number.
     * Selection is by unit number, never by map iteration order.
     *
     * @param serialNumberToUnitNumber serial number to unit number of the units currently retrieved from the stack
     * @return serial number of the default unit, or null if no units were retrieved
     * */
    public static String defaultManagementUnitSerialNumber(Map<String, String> serialNumberToUnitNumber) {
        String defaultSerialNumber = null;
        long lowestUnitNumber = Long.MAX_VALUE;
        for (Map.Entry<String, String> entry : serialNumberToUnitNumber.entrySet()) {
            String unitNumber = entry.getValue();
            long parsedUnitNumber = StringUtils.isNullOrEmpty(unitNumber) ? Long.MAX_VALUE : extractNumber(unitNumber);
            if (defaultSerialNumber == null || parsedUnitNumber < lowestUnitNumber
                    || (parsedUnitNumber == lowestUnitNumber && entry.getKey().compareTo(defaultSerialNumber) < 0)) {
                defaultSerialNumber = entry.getKey();
                lowestUnitNumber = parsedUnitNumber;
            }
        }
        return defaultSerialNumber;
    }
}

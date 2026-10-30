/*
 * Copyright (c) 2026 AVI-SPL, Inc. All Rights Reserved.
 */
package com.avispl.symphony.dal.netgear.avapi.utils;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.ServiceConfigurationError;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link Utils#resolveManagementUnitSerialNumber(String, java.util.Collection)}, no device needed
 *
 * @author Yashas.CN/AVISPL Team
 * */
public class ManagementUnitSerialNumberResolverTest {
    private static final List<String> SINGLE_UNIT = Collections.singletonList("74W12C57F000F");
    private static final List<String> STACK = Arrays.asList("74W12C57F000F", "74W12C57F0010");

    @Test
    public void testConfiguredSerialNumberPresentInStack() {
        assertEquals("74W12C57F0010", Utils.resolveManagementUnitSerialNumber("74W12C57F0010", STACK));
    }

    @Test
    public void testConfiguredSerialNumberNotInStack() {
        ServiceConfigurationError error = assertThrows(ServiceConfigurationError.class,
                () -> Utils.resolveManagementUnitSerialNumber("UNKNOWN0001", STACK));
        assertTrue(error.getMessage().contains("UNKNOWN0001"), "Error message should name the configured serial number");
    }

    @Test
    public void testNoSerialNumberSingleUnit() {
        assertEquals("74W12C57F000F", Utils.resolveManagementUnitSerialNumber(null, SINGLE_UNIT));
        assertEquals("74W12C57F000F", Utils.resolveManagementUnitSerialNumber("", SINGLE_UNIT));
    }

    @Test
    public void testNoSerialNumberMultipleUnits() {
        ServiceConfigurationError error = assertThrows(ServiceConfigurationError.class,
                () -> Utils.resolveManagementUnitSerialNumber(null, STACK));
        assertTrue(error.getMessage().startsWith("Management unit serial number (managementUnitSerialNumber) is not configured, ambiguous monitoring settings"));
    }

    @Test
    public void testNoSerialNumberNoUnits() {
        assertThrows(IllegalStateException.class,
                () -> Utils.resolveManagementUnitSerialNumber(null, Collections.emptyList()));
    }
}

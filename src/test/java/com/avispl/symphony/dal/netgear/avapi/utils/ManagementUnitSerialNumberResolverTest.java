/*
 * Copyright (c) 2026 AVI-SPL, Inc. All Rights Reserved.
 */
package com.avispl.symphony.dal.netgear.avapi.utils;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.ServiceConfigurationError;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link Utils#resolveManagementUnitSerialNumber(String, Map)} and
 * {@link Utils#defaultManagementUnitSerialNumber(Map)}, no device needed
 *
 * @author Yashas.CN/AVISPL Team
 * */
public class ManagementUnitSerialNumberResolverTest {
    private static final String UNIT_1_SERIAL = "74W12C57F000F";
    private static final String UNIT_2_SERIAL = "74W12C57F0010";

    private static final Map<String, String> SINGLE_UNIT = Collections.singletonMap(UNIT_1_SERIAL, "1");

    /** Serial number to unit number, inserted unit 2 first so iteration order does not match unit order */
    private static Map<String, String> stack(String... serialAndUnitPairs) {
        Map<String, String> stack = new LinkedHashMap<>();
        for (int i = 0; i < serialAndUnitPairs.length; i += 2) {
            stack.put(serialAndUnitPairs[i], serialAndUnitPairs[i + 1]);
        }
        return stack;
    }

    private static final Map<String, String> TWO_UNIT_STACK = stack(UNIT_2_SERIAL, "2", UNIT_1_SERIAL, "1");

    @Test
    public void testConfiguredSerialNumberPresentInStack() {
        assertEquals(UNIT_2_SERIAL, Utils.resolveManagementUnitSerialNumber(UNIT_2_SERIAL, TWO_UNIT_STACK));
        assertEquals(UNIT_1_SERIAL, Utils.resolveManagementUnitSerialNumber(UNIT_1_SERIAL, TWO_UNIT_STACK));
    }

    @Test
    public void testConfiguredSerialNumberNotInStack() {
        ServiceConfigurationError error = assertThrows(ServiceConfigurationError.class,
                () -> Utils.resolveManagementUnitSerialNumber("UNKNOWN0001", TWO_UNIT_STACK));
        assertTrue(error.getMessage().contains("UNKNOWN0001"), "Error message should name the configured serial number");
    }

    @Test
    public void testNoSerialNumberSingleUnit() {
        assertEquals(UNIT_1_SERIAL, Utils.resolveManagementUnitSerialNumber(null, SINGLE_UNIT));
        assertEquals(UNIT_1_SERIAL, Utils.resolveManagementUnitSerialNumber("", SINGLE_UNIT));
    }

    @Test
    public void testNoSerialNumberSingleUnitNotNumberedOne() {
        assertEquals(UNIT_2_SERIAL, Utils.resolveManagementUnitSerialNumber(null, Collections.singletonMap(UNIT_2_SERIAL, "2")));
    }

    @Test
    public void testNoSerialNumberTwoUnitStackFallsBackToUnitOne() {
        assertEquals(UNIT_1_SERIAL, Utils.resolveManagementUnitSerialNumber(null, TWO_UNIT_STACK));
        assertEquals(UNIT_1_SERIAL, Utils.resolveManagementUnitSerialNumber("", TWO_UNIT_STACK));
    }

    @Test
    public void testNoSerialNumberSelectsByUnitNumberNotIterationOrder() {
        Map<String, String> stack = stack("SERIAL_U3", "3", "SERIAL_U10", "10", "SERIAL_U1", "1", "SERIAL_U2", "2");
        assertEquals("SERIAL_U1", Utils.resolveManagementUnitSerialNumber(null, stack));
    }

    @Test
    public void testNoSerialNumberNoUnitOneFallsBackToLowestUnit() {
        Map<String, String> stack = stack("SERIAL_U3", "3", "SERIAL_U2", "2");
        assertEquals("SERIAL_U2", Utils.resolveManagementUnitSerialNumber(null, stack));
    }

    @Test
    public void testNoSerialNumberNoUnits() {
        assertThrows(IllegalStateException.class,
                () -> Utils.resolveManagementUnitSerialNumber(null, Collections.emptyMap()));
        assertNull(Utils.defaultManagementUnitSerialNumber(Collections.emptyMap()));
    }
}

/*
 * Copyright (c) 2026 AVI-SPL, Inc. All Rights Reserved.
 */
package com.avispl.symphony.dal.netgear.avapi.utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link Utils#isUnitActive(String)}, no device needed
 *
 * @author Yashas.CN/AVISPL Team
 * */
public class UnitActiveTest {

    @Test
    public void testActiveTrue() {
        assertTrue(Utils.isUnitActive("true"));
    }

    @Test
    public void testActiveFalse() {
        assertFalse(Utils.isUnitActive("false"));
    }

    @Test
    public void testActiveMissing() {
        assertFalse(Utils.isUnitActive(null));
        assertFalse(Utils.isUnitActive(""));
        assertFalse(Utils.isUnitActive("   "));
    }

    @Test
    public void testActiveBooleanAsText() {
        assertTrue(Utils.isUnitActive("TRUE"));
        assertTrue(Utils.isUnitActive("True"));
        assertTrue(Utils.isUnitActive(" true "));
        assertFalse(Utils.isUnitActive("FALSE"));
        assertFalse(Utils.isUnitActive("Not Present"));
    }
}

/*
 * Copyright (c) 2024 AVI-SPL, Inc. All Rights Reserved.
 */
package com.avispl.symphony.dal.netgear.avapi.utils;

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
}

package de.mtg.jzlint.utils;

import java.util.Optional;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StringUtilsTest {

    @ParameterizedTest
    @CsvSource({
            "example.com, com",
            "test.example.com, com",
            ",",
            "nodot,",
            "lastdot.,",
    })
    void testGetAfterLastDot(String input, String expectedResult) {
        Optional<String> result = StringUtils.getAfterLastDot(input);

        if (expectedResult == null) {
            assertFalse(result.isPresent());
        } else {
            assertTrue(result.isPresent());
            assertEquals(expectedResult, result.get());
        }

    }

    @ParameterizedTest
    @CsvSource({
            "test.example.com, example.com",
            "a.test.example.com, test.example.com",
            ",",
            "nodot,",
            "lastdot.,",
    })
    void testGetAfterFirstDot(String input, String expectedResult) {
        Optional<String> result = StringUtils.getAfterFirstDot(input);

        if (expectedResult == null) {
            assertFalse(result.isPresent());
        } else {
            assertTrue(result.isPresent());
            assertEquals(expectedResult, result.get());
        }

    }

    @ParameterizedTest
    @CsvSource({
            "example.com, example",
            "test.example.com, test.example",
            ",",
            "nodot,",
            "lastdot.,lastdot",
    })
    void testGetBeforeLastDot(String input, String expectedResult) {
        Optional<String> result = StringUtils.getBeforeLastDot(input);

        if (expectedResult == null) {
            assertFalse(result.isPresent());
        } else {
            assertTrue(result.isPresent());
            assertEquals(expectedResult, result.get());
        }

    }

    @ParameterizedTest
    @CsvSource({
            "string,,",
            ",string,",
            "endingnomatch,wrong,",
            "test.press.cy,.press.cy,test",
    })
    void testGetWithoutEnding(String input, String ending, String expectedResult) {
        Optional<String> result = StringUtils.getWithoutEnding(input, ending);
        if (expectedResult == null) {
            assertFalse(result.isPresent());
        } else {
            assertTrue(result.isPresent());
            assertEquals(expectedResult, result.get());
        }
    }

    @ParameterizedTest
    @CsvSource({
            ".test,test",
            ".test.,test.",
            "test,test",
            "..test,test",
            ".. test,' test'",
            "......,''",
    })
    void testRemoveAllLeadingDots(String input, String expectedResult) {
        String result = StringUtils.removeAllLeadingDots(input);
        assertEquals(expectedResult, result);
    }

    @ParameterizedTest
    @CsvSource({
            "test.,test",
            ".test.,.test",
            "test,test",
            "test..,test",
            "test ..,'test '",
            "......,''",
    })
    void testRemoveAllTrailingDots(String input, String expectedResult) {
        String result = StringUtils.removeAllTrailingDots(input);
        assertEquals(expectedResult, result);
    }

}
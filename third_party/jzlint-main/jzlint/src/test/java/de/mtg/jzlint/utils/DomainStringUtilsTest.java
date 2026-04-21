package de.mtg.jzlint.utils;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class DomainStringUtilsTest {

    @Test
    void testGetLabels() {

        {
            List<String> result = DomainStringUtils.getLabels(".test.example.com");
            assertNotNull(result);
            assertEquals(3, result.size());
            assertEquals("com", result.get(0));
            assertEquals("example", result.get(1));
            assertEquals("test", result.get(2));
        }

        List<String> result = DomainStringUtils.getLabels("test");
        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals("test", result.get(0));
    }

    @ParameterizedTest
    @CsvSource({
            "example.com,example.com,true",
            "example.com,test.example.com,false",
            "test.example.com,*.example.com,true",
            "test.example.com,example.com,true",
            "exampla.com,example.com,false",
    })
    void testRemoveAllLeadingDots(String domain, String rule, String expectedResult) {
        assertEquals(Boolean.parseBoolean(expectedResult), DomainStringUtils.domainMatches(domain, rule));
    }

    @ParameterizedTest
    @CsvSource({
            "'',false",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,false",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,true",
            "9,true",
            "9a,true",
            "a9,true",
            "a,true",
            ".,false",
            "a-b,true",
            "-a,false",
            "a-,false",
            "-,false",
            "%,false",
    })
    void testIsLDHLabel(String label, String expectedResult) {
        assertEquals(Boolean.parseBoolean(expectedResult), DomainStringUtils.isLDHLabel(label));
    }

}
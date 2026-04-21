package de.mtg.jzlint.utils;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;

class ParsedDomainNameUtilsTest {

    @Test
    void testContainsError() {

        {
            List<ParsedDomainName> parsedDomainNameList = new ArrayList<>();
            assertFalse(ParsedDomainNameUtils.containsError(parsedDomainNameList));
        }

        {
            List<ParsedDomainName> parsedDomainNameList = new ArrayList<>();
            parsedDomainNameList.add(ParsedDomainName.fromDomain("example.com"));
            assertFalse(ParsedDomainNameUtils.containsError(parsedDomainNameList));
        }

        {
            List<ParsedDomainName> parsedDomainNameList = new ArrayList<>();
            parsedDomainNameList.add(ParsedDomainName.fromDomain("example.com"));
            parsedDomainNameList.add(ParsedDomainName.fromDomain("example.com.nonexistent"));
            assertFalse(ParsedDomainNameUtils.containsError(parsedDomainNameList));
        }
    }

}
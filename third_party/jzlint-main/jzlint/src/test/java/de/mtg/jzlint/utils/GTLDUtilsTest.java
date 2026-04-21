package de.mtg.jzlint.utils;

import java.io.IOException;
import java.text.ParseException;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GTLDUtilsTest {

    @Test
    void gtldExists() throws IOException {

        assertTrue(GTLDUtils.gtldExists("example.com"));
        assertFalse(GTLDUtils.gtldExists("example.invalidtld"));
    }

    @Test
    void gtldExisted() throws IOException, ParseException {
        ZonedDateTime zonedDateTime = ZonedDateTime.now();
        assertTrue(GTLDUtils.gtldExisted("example.com", zonedDateTime));
        assertFalse(GTLDUtils.gtldExisted("example.com", zonedDateTime.minus(200, ChronoUnit.YEARS)));
        assertFalse(GTLDUtils.gtldExisted("example.invalidtld", zonedDateTime));
    }
}
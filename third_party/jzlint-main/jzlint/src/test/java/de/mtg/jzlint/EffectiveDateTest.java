package de.mtg.jzlint;

import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZonedDateTime;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EffectiveDateTest {

    @Test
    void test() {

        ZonedDateTime zonedDateTime = ZonedDateTime.of(1999, 01, 01, 0, 0, 0, 0, ZoneId.of("UTC"));

        assertFalse(EffectiveDate.RFC2459.getZonedDateTime().isBefore(zonedDateTime));
        assertFalse(EffectiveDate.RFC2459.getZonedDateTime().isAfter(zonedDateTime));
        assertTrue(EffectiveDate.RFC2459.getZonedDateTime().toLocalDate().isBefore(LocalDate.now(ZoneId.of("UTC"))));

    }

}
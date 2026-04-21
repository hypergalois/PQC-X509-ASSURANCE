package de.mtg.jzlint.utils;

import java.security.Security;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DateUtilsTest {

    public static final String CERTIFICATE_TYPE = "X.509";

    @BeforeAll
    static void addProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @ParameterizedTest
    @CsvSource({"6000,5000,1", "86403,3,2", "86402,3,1", "172803,3,3", "172802,3,2"})
    void getValidityInDays(String end, String start, String expected) {
        Long startLong = Long.parseLong(start);
        Long endLong = Long.parseLong(end);
        Integer expectedInteger = Integer.parseInt(expected);
        assertEquals(expectedInteger.intValue(), DateUtils.getValidityInDays(endLong, startLong));
    }

    @ParameterizedTest
    @CsvSource({
            "2022-01-03 08:00:00,2022-01-01 08:00:00,2",
            "2022-01-03 08:00:01,2022-01-01 08:00:00,3",
            "2023-01-01 08:00:00,2022-01-01 08:00:00,365"})
    void getValidityInDaysBeforeSC31(String end, String start, String expected) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.of("UTC"));
        ZonedDateTime endZDT = ZonedDateTime.parse(end, formatter);
        ZonedDateTime startZDT = ZonedDateTime.parse(start, formatter);
        Integer expectedInteger = Integer.parseInt(expected);
        assertEquals(expectedInteger.intValue(), DateUtils.getValidityInDaysBeforeSC31(endZDT, startZDT));
    }

    @ParameterizedTest
    @CsvSource({
            "2022-03-01 08:00:00,2022-01-01 08:00:00,3",
            "2022-03-01 08:00:00,2022-01-02 08:00:00,2",
            "2023-03-01 08:00:00,2022-01-02 08:00:00,14",
            "2023-03-01 08:00:00,2022-01-01 08:00:00,15"})
    void getValidityInMonths(String end, String start, String expected) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.of("UTC"));
        ZonedDateTime endZDT = ZonedDateTime.parse(end, formatter);
        ZonedDateTime startZDT = ZonedDateTime.parse(start, formatter);
        Integer expectedInteger = Integer.parseInt(expected);
        assertEquals(expectedInteger.intValue(), DateUtils.getValidityInMonths(endZDT, startZDT));
    }

    @ParameterizedTest
    @CsvSource({
            "2022-03-01 08:00:00,2022-01-01 08:00:00,2",
            "2022-03-01 08:00:01,2022-01-01 08:00:00,3",
            "2022-03-01 08:00:00,2022-01-02 08:00:00,2",
            "2023-03-01 08:00:00,2022-01-02 08:00:00,14",
            "2023-03-01 08:00:00,2022-01-01 08:00:00,14"})
    void getValidityInMonthsBeforeSC31(String end, String start, String expected) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.of("UTC"));
        ZonedDateTime endZDT = ZonedDateTime.parse(end, formatter);
        ZonedDateTime startZDT = ZonedDateTime.parse(start, formatter);
        Integer expectedInteger = Integer.parseInt(expected);
        assertEquals(expectedInteger.intValue(), DateUtils.getValidityInMonthsBeforeSC31(endZDT, startZDT));
    }

}
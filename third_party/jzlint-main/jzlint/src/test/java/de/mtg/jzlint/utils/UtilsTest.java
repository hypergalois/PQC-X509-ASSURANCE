package de.mtg.jzlint.utils;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;

import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DERVisibleString;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UtilsTest {

    @ParameterizedTest
    @ValueSource(ints = {20, 120, 220, 70000})
    void testGetContentUTF8(int length) throws IOException {
        String string = getStringOfLength(length);
        byte[] content = Utils.getContent(new DERUTF8String(string));
        assertEquals(length, content.length);
        assertTrue(stringContainsOnly(content, 'A'));
    }

    @ParameterizedTest
    @ValueSource(ints = {20, 120, 220, 70000})
    void testGetContentBMP(int length) throws IOException {
        String string = getStringOfLength(length);
        byte[] content = Utils.getContent(new DERBMPString(string));
        assertEquals(length * 2, content.length);
    }

    @ParameterizedTest
    @ValueSource(ints = {20, 120, 220, 70000})
    void testGetContentVisible(int length) throws IOException {
        String string = getStringOfLength(length);
        byte[] content = Utils.getContent(new DERVisibleString(string));
        assertEquals(length, content.length);
        assertTrue(stringContainsOnly(content, 'A'));
    }

    @ParameterizedTest
    @CsvSource({"example.com,false", "198.51.100.3,true", "2001:DB8::,true", "examp:le.com,false"})
    void testIsIPAddress(String value, String expectedResult) {
        assertEquals(Boolean.parseBoolean(expectedResult), Utils.isIPAddress(value));
    }

    @Test
    void testSqrt() {
        for (int i = 0; i < 200; i++) {
           BigInteger number = new BigInteger(1024, new Random());
            BigInteger sqrt = Utils.calculateSquareRoot(number);

            assertEquals(-1, sqrt.pow(2).subtract(number).compareTo(BigInteger.ZERO));
            assertEquals(1, sqrt.add(BigInteger.ONE).pow(2).subtract(number).compareTo(BigInteger.ZERO));
        }
    }

    private String getStringOfLength(int length) {
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < length; i++) {
            stringBuilder.append("A");
        }
        return stringBuilder.toString();
    }

    private boolean stringContainsOnly(byte[] input, char character) {
        for (byte byteCharacter : input) {
            if (byteCharacter != character) {
                return false;
            }
        }
        return true;
    }




}
package de.mtg.jzlint;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import de.mtg.jzlint.utils.IPUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;

class IPUtilsTest {


    @ParameterizedTest
    @CsvSource({
            "172.16.0.0/12,172.16.0.0,true",
            "172.16.0.0/12,172.16.0.1,true",
            "172.16.0.0/12,172.16.0.1,true",
            "172.16.0.0/12,172.31.255.254,true",
            "172.16.0.0/12,172.31.255.255,true",
            "172.16.0.0/12,172.32.0.1,false",
            "192.52.193.0/24,192.52.193.1,true",
            "192.52.193.0/24,192.52.193.1,true",
            "192.52.193.0/24,192.52.193.255,true",
            "192.52.193.0/24,192.52.194.1,false",
    })
    void testIsInRange(String network, String ip, String expected) {
        assertEquals(Boolean.parseBoolean(expected), IPUtils.isIPInRange(network, ip));
    }


    @ParameterizedTest
    @CsvSource({
            "172.16.0.0,true",
            "172.16.0.1,true",
            "172.16.0.1,true",
            "172.31.255.254,true",
            "172.31.255.255,true",
            "172.32.0.1,false",
            "192.52.193.1,true",
            "192.52.193.1,true",
            "192.52.193.255,true",
            "192.52.194.1,false",
            "2001:db8:2001:2001:2001:2001:2001:2001,true",
    })
    void testIsReserved(String ip, String expected) {
        assertEquals(Boolean.parseBoolean(expected), IPUtils.isReservedIP(ip));
    }

    @ParameterizedTest
    @CsvSource({
            "172.16.0.0,true",
            "192.52.193.255,true",
            "abc,false",
            "a.b.c.d,false",
            "2001:db8:2001:2001:2001:2001:2001:2001,true",
    })
    void testIsIP(String ip, String expected) {
        assertEquals(Boolean.parseBoolean(expected), IPUtils.isIP(ip));
    }

}

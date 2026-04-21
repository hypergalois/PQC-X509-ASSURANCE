package de.mtg.jzlint.utils;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ParsedDomainNameTest {

    @ParameterizedTest
    @CsvSource({
            "example.com,com,example,,,",
            "test.example.com,com,example,test,",
            "test2.test1.example.com,com,example,test2.test1,",
            "www.ck,ck,www,,",
            "sld.test.ck,test.ck,sld,,",
            "test.ck,,,," + ParsedDomainName.ERROR_INVALID_DOMAIN,
            "cy,,,," + ParsedDomainName.ERROR_INVALID_DOMAIN,
            "press.cy,,,," + ParsedDomainName.ERROR_INVALID_DOMAIN,
            "sld.press.cy,press.cy,sld,,",
            "trd.sld.press.cy,press.cy,sld,trd,",
            "trd2.trd1.sld.cy,cy,sld,trd2.trd1,",
            "*.wrong*.error.example.com,com,example,*.wrong*.error,",
            "example.nagoya.jp,,,," + ParsedDomainName.ERROR_INVALID_DOMAIN,
            "sld.example.nagoya.jp,example.nagoya.jp,sld,,",
            "trd.sld.example.nagoya.jp,example.nagoya.jp,sld,trd,",
            "city.nagoya.jp,nagoya.jp,city,,",
            "trd.city.nagoya.jp,nagoya.jp,city,trd,",
            "example.notexistent,notexistent,example,,",
            "example.com.ua,com.ua,example,,",
            "cc.ua,ua,cc,,", // private
            "example.cc.ua,ua,cc,example,", // private
            "*.cc.ua,ua,cc,*,", // private
            "611.to,to,611,,", // private
            "graphox.us,us,graphox,,", // private
            "*.devcdnaccesso.com,com,devcdnaccesso,*,", // private
            "s3.dualstack.eu-west-3.amazonaws.com,com,amazonaws,s3.dualstack.eu-west-3,", // private
            "*.appspot.com,com,appspot,*,", // private
            "dh.bytemark.co.uk,co.uk,bytemark,dh,", // private
            "test.鹿児島.jp,鹿児島.jp,test,,", // public, unicode
    })
    void testFromDomainPublic(String domain, String tld, String sld, String trd, String error) {

        ParsedDomainName parsedDomainName = ParsedDomainName.fromDomain(domain);

        if (error != null && !error.isEmpty()) {
            assertEquals("", parsedDomainName.getTld());
            assertEquals("", parsedDomainName.getSld());
            assertEquals("", parsedDomainName.getTrd());
            assertEquals(error, parsedDomainName.getError());
            return;
        }
        assertEquals(tld, parsedDomainName.getTld(), "Wrong TLD");
        assertEquals(sld, parsedDomainName.getSld(), "Wrong SLD");

        if (trd == null) {
            assertEquals("", parsedDomainName.getTrd(), "Wrong TRD");
        } else {
            assertEquals(trd, parsedDomainName.getTrd(), "Wrong TRD");
        }

    }

}
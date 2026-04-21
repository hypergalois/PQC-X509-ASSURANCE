package de.mtg.jzlint;

import java.time.ZoneId;
import java.time.ZonedDateTime;

public enum EffectiveDate {

    ZERO(ZonedDateTime.of(0, 1, 1, 0, 0, 0, 0, ZoneId.of("UTC"))),
    RFC1035(ZonedDateTime.of(1987, 1, 1, 0, 0, 0, 0, ZoneId.of("UTC"))),
    RFC2459(ZonedDateTime.of(1999, 1, 1, 0, 0, 0, 0, ZoneId.of("UTC"))),
    RFC3279(ZonedDateTime.of(2002, 4, 1, 0, 0, 0, 0, ZoneId.of("UTC"))),
    RFC3280(ZonedDateTime.of(2002, 4, 1, 0, 0, 0, 0, ZoneId.of("UTC"))),
    RFC3490(ZonedDateTime.of(2003, 3, 1, 0, 0, 0, 0, ZoneId.of("UTC"))),
    RFC8399(ZonedDateTime.of(2018, 5, 1, 0, 0, 0, 0, ZoneId.of("UTC"))),
    RFC4325(ZonedDateTime.of(2005, 12, 1, 0, 0, 0, 0, ZoneId.of("UTC"))),
    RFC4630(ZonedDateTime.of(2006, 8, 1, 0, 0, 0, 0, ZoneId.of("UTC"))),
    RFC5280(ZonedDateTime.of(2008, 5, 1, 0, 0, 0, 0, ZoneId.of("UTC"))),
    RFC6818(ZonedDateTime.of(2013, 1, 1, 0, 0, 0, 0, ZoneId.of("UTC"))),
    RFC6960(ZonedDateTime.of(2013, 6, 1, 0, 0, 0, 0, ZoneId.of("UTC"))),
    RFC8813(ZonedDateTime.of(2020, 8, 1, 0, 0, 0, 0, ZoneId.of("UTC"))),
    CABEffectiveDate(ZonedDateTime.of(2012, 7, 1, 0, 0, 0, 0, ZoneId.of("UTC"))),
    CABReservedIPDate(ZonedDateTime.of(2016, 10, 1, 0, 0, 0, 0, ZoneId.of("UTC"))),
    CABGivenNameDate(ZonedDateTime.of(2016, 9, 7, 0, 0, 0, 0, ZoneId.of("UTC"))),
    CABSerialNumberEntropyDate(ZonedDateTime.of(2016, 9, 30, 0, 0, 0, 0, ZoneId.of("UTC"))),
    CABV102Date(ZonedDateTime.of(2012, 6, 8, 0, 0, 0, 0, ZoneId.of("UTC"))),
    CABV113Date(ZonedDateTime.of(2013, 2, 21, 0, 0, 0, 0, ZoneId.of("UTC"))),
    CABV114Date(ZonedDateTime.of(2013, 5, 3, 0, 0, 0, 0, ZoneId.of("UTC"))),
    CABV116Date(ZonedDateTime.of(2013, 7, 29, 0, 0, 0, 0, ZoneId.of("UTC"))),
    CABV130Date(ZonedDateTime.of(2015, 4, 16, 0, 0, 0, 0, ZoneId.of("UTC"))),
    CABV131Date(ZonedDateTime.of(2015, 9, 28, 0, 0, 0, 0, ZoneId.of("UTC"))),
    CABV170Date(ZonedDateTime.of(2020, 1, 31, 0, 0, 0, 0, ZoneId.of("UTC"))),
    NO_SHA1(ZonedDateTime.of(2016, 1, 1, 0, 0, 0, 0, ZoneId.of("UTC"))),
    NoRSA1024RootDate(ZonedDateTime.of(2011, 1, 1, 0, 0, 0, 0, ZoneId.of("UTC"))),
    NoRSA1024Date(ZonedDateTime.of(2014, 1, 1, 0, 0, 0, 0, ZoneId.of("UTC"))),
    GeneralizedDate(ZonedDateTime.of(2050, 1, 1, 0, 0, 0, 0, ZoneId.of("UTC"))),
    NoReservedIP(ZonedDateTime.of(2015, 11, 1, 0, 0, 0, 0, ZoneId.of("UTC"))),
    SubCert39Month(ZonedDateTime.of(2016, 7, 2, 0, 0, 0, 0, ZoneId.of("UTC"))),
    SubCert825Days(ZonedDateTime.of(2018, 3, 2, 0, 0, 0, 0, ZoneId.of("UTC"))),
    CABV148Date(ZonedDateTime.of(2017, 6, 8, 0, 0, 0, 0, ZoneId.of("UTC"))),
    EtsiEn319_412_5_V2_2_1_Date(ZonedDateTime.of(2017, 11, 1, 0, 0, 0, 0, ZoneId.of("UTC"))),
    OnionOnlyEVDate(ZonedDateTime.of(2015, 5, 1, 0, 0, 0, 0, ZoneId.of("UTC"))),
    CABV201Date(ZonedDateTime.of(2017, 7, 28, 0, 0, 0, 0, ZoneId.of("UTC"))),
    AppleCTPolicyDate(ZonedDateTime.of(2018, 10, 15, 0, 0, 0, 0, ZoneId.of("UTC"))),
    MozillaPolicy22Date(ZonedDateTime.of(2013, 7, 26, 0, 0, 0, 0, ZoneId.of("UTC"))),
    MozillaPolicy24Date(ZonedDateTime.of(2017, 2, 28, 0, 0, 0, 0, ZoneId.of("UTC"))),
    MozillaPolicy241Date(ZonedDateTime.of(2017, 3, 31, 0, 0, 0, 0, ZoneId.of("UTC"))),
    MozillaPolicy27Date(ZonedDateTime.of(2020, 1, 1, 0, 0, 0, 0, ZoneId.of("UTC"))),
    CABFBRs_1_6_2_UnderscorePermissibilitySunsetDate(ZonedDateTime.of(2019, 4, 1, 0, 0, 0, 0, ZoneId.of("UTC"))),
    CABFBRs_1_6_2_Date(ZonedDateTime.of(2018, 12, 10, 0, 0, 0, 0, ZoneId.of("UTC"))),
    CABFBRs_1_2_1_Date(ZonedDateTime.of(2015, 1, 16, 0, 0, 0, 0, ZoneId.of("UTC"))),
    CABFBRs_1_6_9_Date(ZonedDateTime.of(2020, 3, 27, 0, 0, 0, 0, ZoneId.of("UTC"))),
    CABFBRs_1_7_1_Date(ZonedDateTime.of(2020, 8, 20, 0, 0, 0, 0, ZoneId.of("UTC"))),
    CABFBRs_1_7_9_Date(ZonedDateTime.of(2021, 8, 16, 0, 0, 0, 0, ZoneId.of("UTC"))),
    AppleReducedLifetimeDate(ZonedDateTime.of(2020, 9, 1, 0, 0, 0, 0, ZoneId.of("UTC"))),
    CABFBRs_1_8_0_Date(ZonedDateTime.of(2021, 8, 25, 0, 0, 0, 0, ZoneId.of("UTC"))),
    CABFBRs_1_8_7_Date(ZonedDateTime.of(2023, 7, 15, 0, 0, 0, 0, ZoneId.of("UTC"))),
    NoReservedDomainLabelsDate(ZonedDateTime.of(2021, 10, 1, 0, 0, 0, 0, ZoneId.of("UTC"))),
    AppleCTPolicy_DURATION_CHANGE(ZonedDateTime.of(2021, 4, 21, 0, 0, 0, 0, ZoneId.of("UTC"))),
    CABFBRs_OU_Prohibited_Date(ZonedDateTime.of(2022, 9, 1, 0, 0, 0, 0, ZoneId.of("UTC"))),
    JANUARY_2019(ZonedDateTime.of(2019, 1, 1, 0, 0, 0, 0, ZoneId.of("UTC"))),
    SMIME_BR_1_0_DATE(ZonedDateTime.of(2023, 9, 1, 0, 0, 0, 0, ZoneId.of("UTC"))),
    CS_BR_3_2_DATE(ZonedDateTime.of(2022, 10, 28, 0, 0, 0, 0, ZoneId.of("UTC"))),
    OCSP_SHA1_SUNSET(ZonedDateTime.of(2022, 3, 4, 0, 0, 0, 0, ZoneId.of("UTC"))),
    CRL_REASON_CODE_UPDATE(ZonedDateTime.of(2020, 9, 30, 0, 0, 0, 0, ZoneId.of("UTC"))),
    SC62_EFFECTIVE_DATE(ZonedDateTime.of(2023, 9, 15, 0, 0, 0, 0, ZoneId.of("UTC"))),

    TR_03109_4_V1_2_1(ZonedDateTime.of(2017, 9, 8, 0, 0, 0, 0, ZoneId.of("UTC")));

    private final ZonedDateTime zonedDateTime;

    EffectiveDate(ZonedDateTime zonedDateTime) {
        this.zonedDateTime = zonedDateTime;
    }

    public ZonedDateTime getZonedDateTime() {
        return zonedDateTime;
    }

}

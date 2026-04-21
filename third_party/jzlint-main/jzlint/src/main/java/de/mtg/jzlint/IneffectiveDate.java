package de.mtg.jzlint;

import java.time.ZoneId;
import java.time.ZonedDateTime;

public enum IneffectiveDate {

    EMPTY(null),
    CABFBRs_1_6_2_Date(ZonedDateTime.of(2018, 12, 10, 0, 0, 0, 0, ZoneId.of("UTC"))),
    CABFBRs_1_7_1_Date(ZonedDateTime.of(2020, 8, 20, 0, 0, 0, 0, ZoneId.of("UTC"))),
    CABFBRs_1_8_0_Date(ZonedDateTime.of(2021, 8, 21, 0, 0, 0, 0, ZoneId.of("UTC"))),
    SC62_EFFECTIVE_DATE(ZonedDateTime.of(2023, 9, 15, 0, 0, 0, 0, ZoneId.of("UTC"))),
    CABFBRS_1_6_2_UNDERSCORE_PERMISSIBILITY_SUNSET_DATE(ZonedDateTime.of(2023, 9, 15, 0, 0, 0, 0, ZoneId.of("UTC")));

    private ZonedDateTime zonedDateTime;

    IneffectiveDate(ZonedDateTime zonedDateTime) {
        this.zonedDateTime = zonedDateTime;
    }

    public ZonedDateTime getZonedDateTime() {
        return zonedDateTime;
    }

}

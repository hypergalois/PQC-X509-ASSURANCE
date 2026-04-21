package de.mtg.jzlint.lints.cabf_ev;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class EvValidTimeTooLongTest {

    @LintTest(
            name = "e_ev_valid_time_too_long",
            filename = "evValidTooLong.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "EV certificate valid for > 27 months")
    void testCase01() {
    }

    @LintTest(
            name = "e_ev_valid_time_too_long",
            filename = "evValidNotTooLong.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "EV certificate issued before Ballot 193 valid for 27 months")
    void testCase02() {
    }

    @LintTest(
            name = "e_ev_valid_time_too_long",
            filename = "evValidNotTooLong825Days.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "EV certificate issued after Ballot 193, valid for 825 days, which is >27 months")
    void testCase03() {
    }

    @LintTest(
            name = "e_ev_valid_time_too_long",
            filename = "27monthsEv.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "EV certificate issued after Ballot 193, valid for 825 days, which is >27 months")
    void testCase04() {
    }

}

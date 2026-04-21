package de.mtg.jzlint.lints.cabf_ev;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class EOnionSubjectValidityTimeTooLargeTest {

    @LintTest(
            name = "e_onion_subject_validity_time_too_large",
            filename = "onionSANLongExpiryPreBallot.pem",
            expectedResultStatus = Status.NE,
            certificateDescription = "Onion subject, long expiry before util.OnionOnlyEVDate")
    void testCase01() {
    }

    @LintTest(
            name = "e_onion_subject_validity_time_too_large",
            filename = "onionSANLongExpiry.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Onion subject, long expiry, after util.OnionOnlyEVDate")
    void testCase02() {
    }

    @LintTest(
            name = "e_onion_subject_validity_time_too_large",
            filename = "onionSANGoodExpiry.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Onion subject, valid expiry")
    void testCase03() {
    }

}
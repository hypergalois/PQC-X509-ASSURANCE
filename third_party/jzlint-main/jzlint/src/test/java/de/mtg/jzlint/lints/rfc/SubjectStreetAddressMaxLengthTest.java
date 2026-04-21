package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubjectStreetAddressMaxLengthTest {

    @LintTest(
            name = "e_subject_street_address_max_length",
            filename = "subjectStreetAddress.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_subject_street_address_max_length",
            filename = "subjectStreetAddressTooLong.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

}
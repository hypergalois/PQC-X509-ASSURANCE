package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubjectDnSerialNumberMaxLengthTest {

    @LintTest(
            name = "e_subject_dn_serial_number_max_length",
            filename = "evAllGood.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_subject_dn_serial_number_max_length",
            filename = "SubjectDNSerialNumberTooLong.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

}
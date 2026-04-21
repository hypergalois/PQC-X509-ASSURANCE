package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SerialNumberLongerThan20OctetsTest {

    @LintTest(
            name = "e_serial_number_longer_than_20_octets",
            filename = "serialNumberLarge.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_serial_number_longer_than_20_octets",
            filename = "serialNumberValid.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

    @LintTest(
            name = "e_serial_number_longer_than_20_octets",
            filename = "serialNumberLargeDueToSignedMSB.pem",
            expectedResultStatus = Status.ERROR)
    void testCase03() {
    }
}
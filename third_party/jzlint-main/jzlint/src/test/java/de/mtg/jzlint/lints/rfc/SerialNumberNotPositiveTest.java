package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SerialNumberNotPositiveTest {

    @LintTest(
            name = "e_serial_number_not_positive",
            filename = "serialNumberNegative.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_serial_number_not_positive",
            filename = "serialNumberValid.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

    @LintTest(
            name = "e_serial_number_not_positive",
            filename = "serialNumberZero.pem",
            expectedResultStatus = Status.ERROR)
    void testCase03() {
    }
}
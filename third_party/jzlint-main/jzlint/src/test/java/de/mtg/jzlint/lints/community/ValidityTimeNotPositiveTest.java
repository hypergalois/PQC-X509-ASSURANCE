package de.mtg.jzlint.lints.community;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ValidityTimeNotPositiveTest {

    @LintTest(
            name = "e_validity_time_not_positive",
            filename = "validityNegative.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_validity_time_not_positive",
            filename = "IANURIValid.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}
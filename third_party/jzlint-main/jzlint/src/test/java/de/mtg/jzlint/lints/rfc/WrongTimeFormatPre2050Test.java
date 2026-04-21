package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class WrongTimeFormatPre2050Test {

    @LintTest(
            name = "e_wrong_time_format_pre2050",
            filename = "generalizedAfter2050.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass cert with NULL params")
    void testCase01() {
    }

    @LintTest(
            name = "e_wrong_time_format_pre2050",
            filename = "orgValGoodAllFields.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "error cert with missing NULL params")
    void testCase02() {
    }

    @LintTest(
            name = "e_wrong_time_format_pre2050",
            filename = "generalizedPrior2050.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "error cert with missing NULL params")
    void testCase03() {
    }
}
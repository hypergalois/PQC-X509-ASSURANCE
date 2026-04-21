package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class UnderscorePresentWithTooLongValidityTest {

    @LintTest(
            name = "e_underscore_present_with_too_long_validity",
            filename = "dNSUnderscoresShortValidity.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "Underscores but 30 day validity")
    void testCase01() {
    }

    @LintTest(
            name = "e_underscore_present_with_too_long_validity",
            filename = "dNSUnderscoresLongValidity.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Underscores with too long validity")
    void testCase02() {
    }

    @LintTest(
            name = "e_underscore_present_with_too_long_validity",
            filename = "dNSNoUnderscoresLongValidity.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "No underscores")
    void testCase03() {
    }

    @LintTest(
            name = "e_underscore_present_with_too_long_validity",
            filename = "dNSUnderscoresPermissibleOutOfDateRange.pem",
            expectedResultStatus = Status.NE,
            certificateDescription = "Not effective")
    void testCase04() {
    }

}

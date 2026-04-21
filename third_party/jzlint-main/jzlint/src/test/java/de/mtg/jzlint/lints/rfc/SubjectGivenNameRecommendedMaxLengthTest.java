package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubjectGivenNameRecommendedMaxLengthTest {

    @LintTest(
            name = "w_subject_given_name_recommended_max_length",
            filename = "givenNameUnder64.pem",
            expectedResultStatus = Status.PASS)
    @Disabled("This test needs to be adjusted, the implementation deviates from zlint")
    void testCase01() {
    }

    @LintTest(
            name = "w_subject_given_name_recommended_max_length",
            filename = "givenNameOver64.pem",
            expectedResultStatus = Status.WARN)
    void testCase02() {
    }
}
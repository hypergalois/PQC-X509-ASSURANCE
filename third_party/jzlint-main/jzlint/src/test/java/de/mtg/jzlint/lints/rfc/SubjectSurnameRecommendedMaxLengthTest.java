package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubjectSurnameRecommendedMaxLengthTest {

    @LintTest(
            name = "w_subject_surname_recommended_max_length",
            filename = "surnameUnder64.pem",
            expectedResultStatus = Status.PASS)
    @Disabled("This test needs to be adjusted, the implementation deviates from zlint")
    void testCase01() {
    }

    @LintTest(
            name = "w_subject_surname_recommended_max_length",
            filename = "surnameOver64.pem",
            expectedResultStatus = Status.WARN)
    void testCase02() {
    }
}
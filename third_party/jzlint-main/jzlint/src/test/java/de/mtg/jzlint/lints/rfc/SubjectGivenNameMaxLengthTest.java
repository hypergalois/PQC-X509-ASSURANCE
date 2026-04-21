package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubjectGivenNameMaxLengthTest {

    @LintTest(
            name = "e_subject_given_name_max_length",
            filename = "givenNameUnder64.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_subject_given_name_max_length",
            filename = "givenNameOver32768.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }
}
package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubjectPostalCodeMaxLengthTest {

    @LintTest(
            name = "e_subject_postal_code_max_length",
            filename = "subjectPostalCode.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_subject_postal_code_max_length",
            filename = "subjectPostalCodeTooLong.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }
}
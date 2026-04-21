package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubjectSurnameMaxLengthTest {

    @LintTest(
            name = "e_subject_surname_max_length",
            filename = "surnameUnder64.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_subject_surname_max_length",
            filename = "surnameOver32768.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }
}
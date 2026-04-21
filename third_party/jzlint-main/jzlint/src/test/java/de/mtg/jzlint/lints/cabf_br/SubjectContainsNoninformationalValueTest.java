package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubjectContainsNoninformationalValueTest {

    @LintTest(
            name = "e_subject_contains_noninformational_value",
            filename = "legalChar.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "simple all legal")
    void testCase01() {
    }

    @LintTest(
            name = "e_subject_contains_noninformational_value",
            filename = "illegalChar.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "subject with metadata only")
    void testCase02() {
    }

}
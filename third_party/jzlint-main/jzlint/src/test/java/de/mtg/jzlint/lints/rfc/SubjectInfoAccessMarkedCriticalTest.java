package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubjectInfoAccessMarkedCriticalTest {

    @LintTest(
            name = "e_subject_info_access_marked_critical",
            filename = "siaCrit.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_subject_info_access_marked_critical",
            filename = "siaNotCrit.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}
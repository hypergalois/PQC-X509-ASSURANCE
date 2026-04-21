package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtSubjectKeyIdentifierCriticalTest {

    @LintTest(
            name = "e_ext_subject_key_identifier_critical",
            filename = "skiCriticalCA.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_subject_key_identifier_critical",
            filename = "skiNotCriticalCA.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}
package de.mtg.jzlint.lints.community;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubjectDnTrailingWhitespaceTest {

    @LintTest(
            name = "w_subject_dn_trailing_whitespace",
            filename = "subjectDNTrailingSpace.pem",
            expectedResultStatus = Status.WARN)
    void testCase01() {
    }

    @LintTest(
            name = "w_subject_dn_trailing_whitespace",
            filename = "domainValGoodSubject.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }
}
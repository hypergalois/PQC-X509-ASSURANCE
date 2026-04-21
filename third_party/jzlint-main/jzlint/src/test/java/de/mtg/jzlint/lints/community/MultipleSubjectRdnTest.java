package de.mtg.jzlint.lints.community;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class MultipleSubjectRdnTest {

    @LintTest(
            name = "n_multiple_subject_rdn",
            filename = "subjectRDNTwoAttribute.pem",
            expectedResultStatus = Status.NOTICE)
    void testCase01() {
    }

    @LintTest(
            name = "n_multiple_subject_rdn",
            filename = "RSASHA1Good.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}
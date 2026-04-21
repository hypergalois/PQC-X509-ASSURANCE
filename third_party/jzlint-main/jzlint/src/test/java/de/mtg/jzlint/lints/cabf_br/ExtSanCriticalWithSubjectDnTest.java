package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtSanCriticalWithSubjectDnTest {

    @LintTest(
            name = "w_ext_san_critical_with_subject_dn",
            filename = "SANCriticalSubjectUncommonOnly.pem",
            expectedResultStatus = Status.WARN)
    void testCase01() {
    }

    @LintTest(
            name = "w_ext_san_critical_with_subject_dn",
            filename = "indivValGoodAllFields.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}
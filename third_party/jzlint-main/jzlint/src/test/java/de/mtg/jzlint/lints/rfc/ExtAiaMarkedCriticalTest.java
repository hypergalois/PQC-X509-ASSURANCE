package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtAiaMarkedCriticalTest {
    @LintTest(
            name = "e_ext_aia_marked_critical",
            filename = "aiaCrit.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_aia_marked_critical",
            filename = "subCAAIAValid.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }
}
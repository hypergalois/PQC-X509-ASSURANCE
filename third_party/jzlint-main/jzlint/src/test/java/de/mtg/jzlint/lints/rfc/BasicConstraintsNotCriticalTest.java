package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class BasicConstraintsNotCriticalTest {

    @LintTest(
            name = "e_basic_constraints_not_critical",
            filename = "caBasicConstNotCrit.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "A CA certificate with non-critical basic constraints")
    void testCase01() {
    }

    @LintTest(
            name = "e_basic_constraints_not_critical",
            filename = "caBasicConstCrit.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "A CA certificate with critical basic constraints")
    void testCase02() {
    }
}
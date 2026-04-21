package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubCertBasicConstraintsNotCriticalTest {

    @LintTest(
            name = "e_sub_cert_basic_constraints_not_critical",
            filename = "basicConstraintsNotCriticalSC62.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_sub_cert_basic_constraints_not_critical",
            filename = "basicConstraintsCriticalSC62.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}

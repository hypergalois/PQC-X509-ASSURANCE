package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubCaNameConstraintsNotCriticalTest {

    @LintTest(
            name = "w_sub_ca_name_constraints_not_critical",
            filename = "subCAWNameConstNoCrit.pem",
            expectedResultStatus = Status.WARN)
    void testCase01() {
    }

    @LintTest(
            name = "w_sub_ca_name_constraints_not_critical",
            filename = "subCAWNameConstCrit.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}

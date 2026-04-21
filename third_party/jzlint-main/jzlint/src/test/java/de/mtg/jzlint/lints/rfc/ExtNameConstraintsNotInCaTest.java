package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtNameConstraintsNotInCaTest {

    @LintTest(
            name = "e_ext_name_constraints_not_in_ca",
            filename = "noNameConstraint.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_name_constraints_not_in_ca",
            filename = "subCAWNameConstCrit.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }
}
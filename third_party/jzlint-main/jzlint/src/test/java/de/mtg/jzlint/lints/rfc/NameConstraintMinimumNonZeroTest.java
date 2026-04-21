package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class NameConstraintMinimumNonZeroTest {

    @LintTest(
            name = "e_name_constraint_minimum_non_zero",
            filename = "ncMinZero.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_name_constraint_minimum_non_zero",
            filename = "ncMinPres.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

}
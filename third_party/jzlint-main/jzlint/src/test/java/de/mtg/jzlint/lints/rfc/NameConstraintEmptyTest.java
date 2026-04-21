package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class NameConstraintEmptyTest {

    @LintTest(
            name = "e_name_constraint_empty",
            filename = "noNameConstraint.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_name_constraint_empty",
            filename = "yesNameConstraint.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }
}
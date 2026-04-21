package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class NameConstraintOnRegisteredIdTest {

    @LintTest(
            name = "w_name_constraint_on_registered_id",
            filename = "ncMinZero.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "w_name_constraint_on_registered_id",
            filename = "ncOnRegId.pem",
            expectedResultStatus = Status.WARN)
    void testCase02() {
    }
}
package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class NameConstraintOnX400Test {

    @LintTest(
            name = "w_name_constraint_on_x400",
            filename = "ncMinZero.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "w_name_constraint_on_x400",
            filename = "ncOnX400.pem",
            expectedResultStatus = Status.WARN)
    @Disabled("The certificate seems to have a wrongly encoded GeneralNames in NameConstraints")
    void testCase02() {
    }
}
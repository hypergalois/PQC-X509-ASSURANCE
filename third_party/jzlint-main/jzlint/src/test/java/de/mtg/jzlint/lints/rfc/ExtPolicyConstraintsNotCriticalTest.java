package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtPolicyConstraintsNotCriticalTest {

    @LintTest(
            name = "e_ext_policy_constraints_not_critical",
            filename = "policyConstNotCritical.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_policy_constraints_not_critical",
            filename = "policyConstGoodBoth.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }
}
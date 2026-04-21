package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class InhibitAnyPolicyNotCriticalTest {

    @LintTest(
            name = "e_inhibit_any_policy_not_critical",
            filename = "inhibitAnyNotCrit.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_inhibit_any_policy_not_critical",
            filename = "inhibitAnyCrit.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}
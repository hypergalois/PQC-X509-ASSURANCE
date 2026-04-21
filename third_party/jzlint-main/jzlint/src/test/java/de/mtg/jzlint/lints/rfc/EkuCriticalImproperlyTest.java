package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class EkuCriticalImproperlyTest {

    @LintTest(
            name = "w_eku_critical_improperly",
            filename = "ekuAnyCrit.pem",
            expectedResultStatus = Status.WARN)
    void testCase01() {
    }

    @LintTest(
            name = "w_eku_critical_improperly",
            filename = "ekuAnyNoCrit.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

    @LintTest(
            name = "w_eku_critical_improperly",
            filename = "ekuNoAnyCrit.pem",
            expectedResultStatus = Status.PASS)
    void testCase03() {
    }


}
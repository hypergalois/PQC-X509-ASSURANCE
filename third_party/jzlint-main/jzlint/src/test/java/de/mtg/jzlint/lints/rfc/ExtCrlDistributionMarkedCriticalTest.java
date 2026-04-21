package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtCrlDistributionMarkedCriticalTest {

    @LintTest(
            name = "w_ext_crl_distribution_marked_critical",
            filename = "subCAWcrlDistCrit.pem",
            expectedResultStatus = Status.WARN)
    void testCase01() {
    }

    @LintTest(
            name = "w_ext_crl_distribution_marked_critical",
            filename = "subCAWcrlDistNoCrit.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}
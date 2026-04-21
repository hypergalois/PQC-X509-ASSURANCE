package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class DistributionPointIncompleteTest {
    @LintTest(
            name = "e_distribution_point_incomplete",
            filename = "crlComlepteDp.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_distribution_point_incomplete",
            filename = "crlIncomlepteDp.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }
}
package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class DsaCorrectOrderInSubgroupTest {

    @LintTest(
            name = "e_dsa_correct_order_in_subgroup",
            filename = "dsaCorrectOrderInSubgroup.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

}
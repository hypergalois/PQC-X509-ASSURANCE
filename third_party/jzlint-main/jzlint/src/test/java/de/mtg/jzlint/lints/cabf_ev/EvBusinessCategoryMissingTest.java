package de.mtg.jzlint.lints.cabf_ev;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class EvBusinessCategoryMissingTest {

    @LintTest(
            name = "e_ev_business_category_missing",
            filename = "evAllGood.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

}
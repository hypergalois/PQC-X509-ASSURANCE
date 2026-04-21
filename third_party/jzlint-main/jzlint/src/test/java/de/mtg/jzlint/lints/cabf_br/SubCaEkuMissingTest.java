package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubCaEkuMissingTest {

    @LintTest(
            name = "n_sub_ca_eku_missing",
            filename = "subCAEKUMissing.pem",
            expectedResultStatus = Status.NOTICE)
    void testCase01() {
    }

    @LintTest(
            name = "n_sub_ca_eku_missing",
            filename = "subCAWEkuCrit.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}

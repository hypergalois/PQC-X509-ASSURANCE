package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubCaEkuNotTechnicallyConstrainedTest {

    @LintTest(
            name = "n_sub_ca_eku_not_technically_constrained",
            filename = "subCAEKUValidFields.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "n_sub_ca_eku_not_technically_constrained",
            filename = "subCAEKUNotValidFields.pem",
            expectedResultStatus = Status.NA)
    @Disabled("NA seems to be the wrong expected result here?")
    void testCase02() {
    }

}

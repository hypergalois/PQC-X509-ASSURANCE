package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubCaAiaMissingWarningTest {

    @LintTest(
            name = "w_sub_ca_aia_missing",
            filename = "subCAAIAValidPostCABFBR171.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - cert valid")
    void testCase01() {
    }

    @LintTest(
            name = "w_sub_ca_aia_missing",
            filename = "subCAAIAMissing.pem",
            expectedResultStatus = Status.NE,
            certificateDescription = "not effective - test case for original subCAAIAMissing lint")
    void testCase02() {
    }

    @LintTest(
            name = "w_sub_ca_aia_missing",
            filename = "subCAAIAMissingPostCABFBR171.pem",
            expectedResultStatus = Status.WARN,
            certificateDescription = "warn - intermediate cert dated after CABF_BR 1.7.1 missing AIA")
    void testCase03() {
    }

}
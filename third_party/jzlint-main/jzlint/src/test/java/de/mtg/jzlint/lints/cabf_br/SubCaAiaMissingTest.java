package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubCaAiaMissingTest {

    @LintTest(
            name = "e_sub_ca_aia_missing",
            filename = "subCAAIAValid.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - cert valid")
    void testCase01() {
    }

    @LintTest(
            name = "e_sub_ca_aia_missing",
            filename = "subCAAIAMissingPostCABFBR171.pem",
            expectedResultStatus = Status.NE,
            certificateDescription = "not effective - test case for CABF_BR 1.7.1 version of lint")
    void testCase02() {
    }

    @LintTest(
            name = "e_sub_ca_aia_missing",
            filename = "subCAAIAMissing.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "error - intermediate cert missing AIA")
    void testCase03() {
    }

}
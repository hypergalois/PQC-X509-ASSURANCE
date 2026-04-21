package de.mtg.jzlint.lints.cabf_smime_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SanShallBePresentTest {

    @LintTest(
            name = "e_san_shall_be_present",
            filename = "smime/with_subject_alternative_name.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - cert with SAN")
    void testCase01() {
    }

    @LintTest(
            name = "e_san_shall_be_present",
            filename = "smime/without_subject_alternative_name.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "error - cert without SAN")
    void testCase02() {
    }

    @LintTest(
            name = "e_san_shall_be_present",
            filename = "smime/with_subject_alternative_name_no_br.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "na - certificate has no SMIME BR policy")
    void testCase03() {
    }


}

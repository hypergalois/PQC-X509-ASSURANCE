package de.mtg.jzlint.lints.cabf_smime_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class KeyUsagePresenceTest {

    @LintTest(
            name = "e_key_usage_presence",
            filename = "smime/rsa_strict_digital_signature_ku.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - cert with KU extension")
    void testCase01() {
    }

    @LintTest(
            name = "e_key_usage_presence",
            filename = "smime/domainValidatedWithEmailCommonName.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "NA - non-SMIME BR cert")
    void testCase02() {
    }

    @LintTest(
            name = "e_key_usage_presence",
            filename = "smime/rsa_strict_valid_ku_august_2023.pem",
            expectedResultStatus = Status.NE,
            certificateDescription = "NE - certificate with KU extension dated before 2020-09-01")
    void testCase03() {
    }

    @LintTest(
            name = "e_key_usage_presence",
            filename = "smime/mailboxValidatedLegacyWithCommonName.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Error - certificate without KU extension")
    void testCase04() {
    }

}
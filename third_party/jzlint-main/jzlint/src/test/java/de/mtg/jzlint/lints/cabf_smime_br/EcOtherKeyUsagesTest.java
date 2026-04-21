package de.mtg.jzlint.lints.cabf_smime_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class EcOtherKeyUsagesTest {

    @LintTest(
            name = "e_ec_other_key_usages",
            filename = "smime/ec_legacy_digital_signature_ku.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - cert with digitalSignature KU")
    void testCase01() {
    }

    @LintTest(
            name = "e_ec_other_key_usages",
            filename = "smime/ec_multipurpose_valid_ku_august_2023.pem",
            expectedResultStatus = Status.NE,
            certificateDescription = "NE - certificate with valid KUs dated before 2020-09-01")
    void testCase02() {
    }

    @LintTest(
            name = "e_ec_other_key_usages",
            filename = "smime/without_subject_alternative_name.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "NA - cert without KUs")
    void testCase03() {
    }

    @LintTest(
            name = "e_ec_other_key_usages",
            filename = "smime/ec_no_key_usages.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "NA - cert with KU extension but no KU bits set")
    void testCase04() {
    }

    @LintTest(
            name = "e_ec_other_key_usages",
            filename = "smime/ec_strict_cert_sign_ku.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Error - Certificate with non-zero KUs without digitalSignature or keyEncipherment KUs")
    void testCase05() {
    }

}
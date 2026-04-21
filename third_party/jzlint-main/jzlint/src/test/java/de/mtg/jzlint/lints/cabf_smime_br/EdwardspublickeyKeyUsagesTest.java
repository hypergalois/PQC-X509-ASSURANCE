package de.mtg.jzlint.lints.cabf_smime_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class EdwardspublickeyKeyUsagesTest {

    @LintTest(
            name = "e_edwardspublickey_key_usages",
            filename = "smime/ed25519_legacy_digital_signature_ku.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - cert with digitalSignature KU")
    void testCase01() {
    }

    @LintTest(
            name = "e_edwardspublickey_key_usages",
            filename = "smime/ed25519_multipurpose_digital_signature_content_commitment_ku.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - cert with digitalSignature and contentCommitment KUs")
    void testCase02() {
    }

    @LintTest(
            name = "e_edwardspublickey_key_usages",
            filename = "smime/domainValidatedWithEmailCommonName.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "NA - non-SMIME BR cert")
    void testCase03() {
    }

    @LintTest(
            name = "e_edwardspublickey_key_usages",
            filename = "smime/rsa_strict_digital_signature_ku.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "NA - RSA cert")
    void testCase04() {
    }

    @LintTest(
            name = "e_edwardspublickey_key_usages",
            filename = "smime/ed25519_strict_valid_ku_august_2023.pem",
            expectedResultStatus = Status.NE,
            certificateDescription = "NE - certificate with KU extension dated before 2020-09-01")
    void testCase05() {
    }

    @LintTest(
            name = "e_edwardspublickey_key_usages",
            filename = "smime/ed25519_strict_cert_sign_ku.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Error - Certificate without digitalSignature KU")
    void testCase06() {
    }

}
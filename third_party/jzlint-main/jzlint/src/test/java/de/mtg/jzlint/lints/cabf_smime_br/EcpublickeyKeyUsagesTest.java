package de.mtg.jzlint.lints.cabf_smime_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class EcpublickeyKeyUsagesTest {

    @LintTest(
            name = "e_ecpublickey_key_usages",
            filename = "smime/ec_legacy_digital_signature_ku.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - cert with digitalSignature KU")
    void testCase01() {
    }

    @LintTest(
            name = "e_ecpublickey_key_usages",
            filename = "smime/ec_multipurpose_digital_signature_content_commitment_ku.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - cert with digitalSignature and contentCommitment KUs")
    void testCase02() {
    }

    @LintTest(
            name = "e_ecpublickey_key_usages",
            filename = "smime/ec_strict_key_agreement_ku.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - cert with keyAgreement KU")
    void testCase03() {
    }

    @LintTest(
            name = "e_ecpublickey_key_usages",
            filename = "smime/ec_legacy_key_agreement_encipher_only_ku.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - cert with keyAgreement and encipherOnly KUs")
    void testCase04() {
    }

    @LintTest(
            name = "e_ecpublickey_key_usages",
            filename = "smime/ec_multipurpose_key_agreement_decipher_only.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - cert with keyAgreement and decipherOnly KUs")
    void testCase05() {
    }

    @LintTest(
            name = "e_ecpublickey_key_usages",
            filename = "smime/ec_strict_digital_signature_key_agreement_content_commitment_encipher_only_ku.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - cert with digitalSignature, keyAgreement, contentCommitment, and encipherOnly KUs")
    void testCase06() {
    }

    @LintTest(
            name = "e_ecpublickey_key_usages",
            filename = "smime/ec_legacy_digital_signature_key_agreement_content_commitment_decipher_only_ku.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - cert with digitalSignature, keyAgreement, contentCommitment, and decipherOnly KUs")
    void testCase07() {
    }

    @LintTest(
            name = "e_ecpublickey_key_usages",
            filename = "smime/without_subject_alternative_name.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "NA - cert without KUs")
    void testCase08() {
    }

    @LintTest(
            name = "e_ecpublickey_key_usages",
            filename = "smime/ec_strict_cert_sign_ku.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "NA - Certificate without digitalSignature or keyAgreement KUs")
    void testCase09() {
    }

    @LintTest(
            name = "e_ecpublickey_key_usages",
            filename = "smime/ec_multipurpose_valid_ku_august_2023.pem",
            expectedResultStatus = Status.NE,
            certificateDescription = "NE - certificate with valid KUs dated before 2020-09-01")
    void testCase10() {
    }

    @LintTest(
            name = "e_ecpublickey_key_usages",
            filename = "smime/ec_strict_digital_signature_cert_sign_ku.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Error - Signing Certificate with unexpected KU")
    void testCase11() {
    }

    @LintTest(
            name = "e_ecpublickey_key_usages",
            filename = "smime/ec_legacy_key_agreement_cert_sign_ku.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Error - Key Management Certificate with unexpected KU")
    void testCase12() {
    }

    @LintTest(
            name = "e_ecpublickey_key_usages",
            filename = "smime/ec_multipurpose_digital_signature_key_agreement_cert_sign_ku.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Error - Dual Use Certificate with unexpected KU")
    void testCase13() {
    }


}
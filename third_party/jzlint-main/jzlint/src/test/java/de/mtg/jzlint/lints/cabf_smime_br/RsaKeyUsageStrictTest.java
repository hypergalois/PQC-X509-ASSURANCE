package de.mtg.jzlint.lints.cabf_smime_br;


import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class RsaKeyUsageStrictTest {

    @LintTest(
            name = "e_rsa_key_usage_strict",
            filename = "smime/rsa_strict_digital_signature_ku.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - cert with digitalSignature KU")
    void testCase01() {
    }

    @LintTest(
            name = "e_rsa_key_usage_strict",
            filename = "smime/rsa_strict_digital_signature_content_commitment_ku.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - cert with digitalSignature and contentCommitment KUs")
    void testCase02() {
    }

    @LintTest(
            name = "e_rsa_key_usage_strict",
            filename = "smime/rsa_strict_key_encipherment_ku.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - cert with keyEncipherment KU")
    void testCase03() {
    }

    @LintTest(
            name = "e_rsa_key_usage_strict",
            filename = "smime/rsa_strict_digital_signature_key_encipherment_content_commitment_ku.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - cert with digitalSignature, keyEncipherment, and contentCommitment KUs")
    void testCase04() {
    }

    @LintTest(
            name = "e_rsa_key_usage_strict",
            filename = "smime/without_subject_alternative_name.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "NA - cert without KUs")
    void testCase05() {
    }

    @LintTest(
            name = "e_rsa_key_usage_strict",
            filename = "smime/rsa_strict_cert_sign_ku.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "NA - Certificate without digitalSignature or keyEncipherment KUs")
    void testCase06() {
    }

    @LintTest(
            name = "e_rsa_key_usage_strict",
            filename = "smime/rsa_strict_valid_ku_august_2023.pem",
            expectedResultStatus = Status.NE,
            certificateDescription = "NE - certificate with valid KUs dated before 2020-09-01")
    void testCase07() {
    }

    @LintTest(
            name = "e_rsa_key_usage_strict",
            filename = "smime/rsa_strict_digital_signature_cert_sign_ku.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Error - Signing Certificate with unexpected KU")
    void testCase08() {
    }

    @LintTest(
            name = "e_rsa_key_usage_strict",
            filename = "smime/rsa_strict_key_encipherment_cert_sign_ku.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Error - Key Management Certificate with unexpected KU")
    void testCase09() {
    }

    @LintTest(
            name = "e_rsa_key_usage_strict",
            filename = "smime/rsa_strict_digital_signature_key_encipherment_cert_sign_ku.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Error - Dual Use Certificate with unexpected KU")
    void testCase10() {
    }

}
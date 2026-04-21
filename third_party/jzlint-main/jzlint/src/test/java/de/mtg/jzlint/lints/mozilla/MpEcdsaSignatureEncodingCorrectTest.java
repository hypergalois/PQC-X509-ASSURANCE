package de.mtg.jzlint.lints.mozilla;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class MpEcdsaSignatureEncodingCorrectTest {

    @LintTest(
            name = "e_mp_ecdsa_signature_encoding_correct",
            filename = "eccP256.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Standard ECC certificate with a P-256 key signed by a P-256 key using SHA256withECDSA")
    void testCase01() {
    }

    @LintTest(
            name = "e_mp_ecdsa_signature_encoding_correct",
            filename = "eccP384.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Standard ECC certificate with a P-384 key signed by a P-384 key using SHA384withECDSA")
    void testCase02() {
    }

    @LintTest(
            name = "e_mp_ecdsa_signature_encoding_correct",
            filename = "eccSignedWithP384ButSHA256Signature.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Standard ECC certificate signed by a P-384 key using SHA256withECDSA")
    void testCase03() {
    }

    @LintTest(
            name = "e_mp_ecdsa_signature_encoding_correct",
            filename = "evAllGood.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "Certificate signed with RSA")
    void testCase04() {
    }

    @LintTest(
            name = "e_mp_ecdsa_signature_encoding_correct",
            filename = "eccSignedWithSHA512Signature.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Standard ECC certificate with a P-256 key signed by a P-256 key using SHA512withECDSA")
    void testCase05() {
    }

    @LintTest(
            name = "e_mp_ecdsa_signature_encoding_correct",
            filename = "eccWithSecp521r1KeySignedWithSHA512Signature.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Standard ECC certificate with a secp521r1 key signed by a secp521r1 key using SHA512withECDSA")
    void testCase06() {
    }

}
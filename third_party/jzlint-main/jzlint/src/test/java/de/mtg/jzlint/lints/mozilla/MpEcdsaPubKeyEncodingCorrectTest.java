package de.mtg.jzlint.lints.mozilla;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class MpEcdsaPubKeyEncodingCorrectTest {

    @LintTest(
            name = "e_mp_ecdsa_pub_key_encoding_correct",
            filename = "eccP256.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Standard ECC certificate with a P-256 key signed by a P-256 key")
    void testCase01() {
    }

    @LintTest(
            name = "e_mp_ecdsa_pub_key_encoding_correct",
            filename = "eccP384.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Standard ECC certificate with a P-384 key signed by a P-384 key")
    void testCase02() {
    }

    @LintTest(
            name = "e_mp_ecdsa_pub_key_encoding_correct",
            filename = "eccP521.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Standard ECC certificate with a P-521 key signed by a P-521 key")
    void testCase03() {
    }

    @LintTest(
            name = "e_mp_ecdsa_pub_key_encoding_correct",
            filename = "evAllGood.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "Certificate with an RSA key")
    void testCase04() {
    }
}
package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SignatureAlgorithmNotSupportedTest {

    @LintTest(
            name = "e_signature_algorithm_not_supported",
            filename = "md5WithRSASignatureAlgorithm.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_signature_algorithm_not_supported",
            filename = "sha1WithRSASignatureAlgorithm.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

    @LintTest(
            name = "e_signature_algorithm_not_supported",
            filename = "sha256WithRSAPSSSignatureAlgorithm.pem",
            expectedResultStatus = Status.WARN)
    void testCase03() {
    }
}
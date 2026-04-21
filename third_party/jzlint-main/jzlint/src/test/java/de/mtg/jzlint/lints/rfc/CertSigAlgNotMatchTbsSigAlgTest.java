package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class CertSigAlgNotMatchTbsSigAlgTest {

    @LintTest(
            name = "e_cert_sig_alg_not_match_tbs_sig_alg",
            filename = "mismatchingSigAlgsBadOID.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "error cert with mismatching signature algorithms (bad OID)")
    void testCase01() {
    }

    @LintTest(
            name = "e_cert_sig_alg_not_match_tbs_sig_alg",
            filename = "mismatchingSigAlgsBadParams.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "error cert with mismatching signature algorithms (bad parameters)")
    void testCase02() {
    }

    @LintTest(
            name = "e_cert_sig_alg_not_match_tbs_sig_alg",
            filename = "ecdsaP256.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass cert with matching signature algorithms")
    void testCase03() {
    }

}
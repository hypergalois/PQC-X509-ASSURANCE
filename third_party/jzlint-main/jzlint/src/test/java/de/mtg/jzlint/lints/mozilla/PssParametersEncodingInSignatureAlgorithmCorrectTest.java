package de.mtg.jzlint.lints.mozilla;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class PssParametersEncodingInSignatureAlgorithmCorrectTest {

    @LintTest(
            name = "e_mp_rsassa-pss_parameters_encoding_in_signature_algorithm_correct",
            filename = "rsassapssWithSHA256.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Standard RSASSA-PSS with SHA256")
    void testCase01() {
    }

    @LintTest(
            name = "e_mp_rsassa-pss_parameters_encoding_in_signature_algorithm_correct",
            filename = "rsassapssWithSHA256EmptyHashParams.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Standard RSASSA-PSS with SHA256 but the hash parameters are empty instead of NULL")
    void testCase02() {
    }

    @LintTest(
            name = "e_mp_rsassa-pss_parameters_encoding_in_signature_algorithm_correct",
            filename = "rsassapssWithSHA384.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Standard RSASSA-PSS with SHA384")
    void testCase03() {
    }

    @LintTest(
            name = "e_mp_rsassa-pss_parameters_encoding_in_signature_algorithm_correct",
            filename = "rsassapssWithSHA384EmptyHashParams.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Standard RSASSA-PSS with SHA384 but the hash parameters are empty instead of NULL")
    void testCase04() {
    }

    @LintTest(
            name = "e_mp_rsassa-pss_parameters_encoding_in_signature_algorithm_correct",
            filename = "rsassapssWithSHA512.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Standard RSASSA-PSS with SHA512")
    void testCase05() {
    }

    @LintTest(
            name = "e_mp_rsassa-pss_parameters_encoding_in_signature_algorithm_correct",
            filename = "rsassapssWithSHA512EmptyHashParams.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Standard RSASSA-PSS with SHA512 but the hash parameters are empty instead of NULL")
    void testCase06() {
    }

    @LintTest(
            name = "e_mp_rsassa-pss_parameters_encoding_in_signature_algorithm_correct",
            filename = "rsassapssWithSHA256ButIrregularSaltLength.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Standard RSASSA-PSS with SHA256 but the salt length is 17 instead of 32")
    void testCase07() {
    }
}
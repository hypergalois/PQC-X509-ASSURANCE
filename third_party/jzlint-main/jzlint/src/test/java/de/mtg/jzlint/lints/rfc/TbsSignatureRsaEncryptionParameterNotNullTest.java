package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class TbsSignatureRsaEncryptionParameterNotNullTest {

    @LintTest(
            name = "e_tbs_signature_rsa_encryption_parameter_not_null",
            filename = "rsawithsha1after2016.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass cert with NULL params")
    void testCase01() {
    }

    @LintTest(
            name = "e_tbs_signature_rsa_encryption_parameter_not_null",
            filename = "rsaSigAlgoNoNULLParam.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "error cert with missing NULL params")
    void testCase02() {
    }
}
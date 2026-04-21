package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SpkiRsaEncryptionParameterNotNullTest {

    @LintTest(
            name = "e_spki_rsa_encryption_parameter_not_null",
            filename = "rsawithsha1after2016.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_spki_rsa_encryption_parameter_not_null",
            filename = "rsaAlgIDNoNULLParams.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

    @LintTest(
            name = "e_spki_rsa_encryption_parameter_not_null",
            filename = "rsaKeyWithParameters.pem",
            expectedResultStatus = Status.ERROR)
    void testCase03() {
    }

}
package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubCertKeyUsageCertSignBitSetTest {

    @LintTest(
            name = "e_sub_cert_key_usage_cert_sign_bit_set",
            filename = "subKeyUsageInvalid.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_sub_cert_key_usage_cert_sign_bit_set",
            filename = "subKeyUsageValid.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}
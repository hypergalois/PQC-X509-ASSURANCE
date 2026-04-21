package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtKeyUsageCertSignWithoutCaTest {

    @LintTest(
            name = "e_ext_key_usage_cert_sign_without_ca",
            filename = "keyUsageCertSignNoBC.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_key_usage_cert_sign_without_ca",
            filename = "caKeyUsageNoCertSign.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }
}
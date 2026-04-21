package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class RootCaExtendedKeyUsagePresentTest {

    @LintTest(
            name = "e_root_ca_extended_key_usage_present",
            filename = "rootCAWithEKU.pem",
            expectedResultStatus = Status.ERROR)
    @Disabled("java.security.cert.CertificateException: signature algorithm in TBS cert not same as outer cert")
    void testCase01() {
    }

    @LintTest(
            name = "e_root_ca_extended_key_usage_present",
            filename = "rootCAValid.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }
}
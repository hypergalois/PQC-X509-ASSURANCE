package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class CaDigitalSignatureNotSetTest {

    @LintTest(
            name = "n_ca_digital_signature_not_set",
            filename = "caKeyUsageNoCertSign.pem",
            expectedResultStatus = Status.NOTICE)
    void testCase01() {
    }

    @LintTest(
            name = "e_ca_crl_sign_not_set",
            filename = "caKeyUsageWDigSign.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }
}
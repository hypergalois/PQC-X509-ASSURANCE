package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubCertEkuExtraValuesTest {

    @LintTest(
            name = "w_sub_cert_eku_extra_values",
            filename = "subExtKeyUsageServClientEmailCodeSign.pem",
            expectedResultStatus = Status.WARN)
    void testCase01() {
    }

    @LintTest(
            name = "w_sub_cert_eku_extra_values",
            filename = "subExtKeyUsageServClientEmail.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}

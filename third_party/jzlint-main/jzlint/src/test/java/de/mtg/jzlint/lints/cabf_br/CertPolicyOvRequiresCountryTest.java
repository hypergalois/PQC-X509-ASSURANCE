package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class CertPolicyOvRequiresCountryTest {

    @LintTest(
            name = "e_cert_policy_ov_requires_country",
            filename = "orgValGoodAllFields.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_cert_policy_ov_requires_country",
            filename = "orgValNoCountry.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }
}
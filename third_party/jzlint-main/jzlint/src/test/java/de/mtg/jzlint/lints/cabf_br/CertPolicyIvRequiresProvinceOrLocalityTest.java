package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class CertPolicyIvRequiresProvinceOrLocalityTest {

    @LintTest(
            name = "e_cert_policy_iv_requires_province_or_locality",
            filename = "indivValGoodAllFields.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_cert_policy_iv_requires_province_or_locality",
            filename = "indivValNoLocalOrProvince.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

}
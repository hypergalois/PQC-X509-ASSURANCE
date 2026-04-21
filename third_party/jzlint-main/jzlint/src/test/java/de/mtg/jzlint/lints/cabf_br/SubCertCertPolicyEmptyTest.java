package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubCertCertPolicyEmptyTest {

    @LintTest(
            name = "e_sub_cert_cert_policy_empty",
            filename = "subCertPolicyMissing.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_sub_cert_cert_policy_empty",
            filename = "subCertPolicyNoCrit.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}
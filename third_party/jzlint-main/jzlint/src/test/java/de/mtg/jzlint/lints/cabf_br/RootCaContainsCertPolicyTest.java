package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class RootCaContainsCertPolicyTest
{
    @LintTest(
            name = "w_root_ca_contains_cert_policy",
            filename = "rootCAWithCertPolicy.pem",
            expectedResultStatus = Status.WARN)
    void testCase01() {
    }

    @LintTest(
            name = "w_root_ca_contains_cert_policy",
            filename = "rootCAValid.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}
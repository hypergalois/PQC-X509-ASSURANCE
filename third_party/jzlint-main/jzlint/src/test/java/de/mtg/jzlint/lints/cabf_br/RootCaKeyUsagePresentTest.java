package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class RootCaKeyUsagePresentTest
{

    @LintTest(
            name = "e_root_ca_key_usage_present",
            filename = "rootCAKeyUsagePresent.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_root_ca_key_usage_present",
            filename = "rootCAKeyUsageMissing.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

}
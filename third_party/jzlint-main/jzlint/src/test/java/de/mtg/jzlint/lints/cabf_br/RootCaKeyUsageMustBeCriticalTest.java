package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class RootCaKeyUsageMustBeCriticalTest {

    @LintTest(
            name = "e_root_ca_key_usage_must_be_critical",
            filename = "rootCAKeyUsagePresent.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_root_ca_key_usage_must_be_critical",
            filename = "rootCAKeyUsageNotCritical.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

}
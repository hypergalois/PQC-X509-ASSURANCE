package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class CaKeyUsageMissingTest {

    @LintTest(
            name = "e_ca_key_usage_missing",
            filename = "caKeyUsageMissing.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_ca_key_usage_missing",
            filename = "caKeyUsageCrit.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }
}
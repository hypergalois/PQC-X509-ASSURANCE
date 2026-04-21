package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtKeyUsageWithoutBitsTest {

    @LintTest(
            name = "e_ext_key_usage_without_bits",
            filename = "keyUsageNoBits.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_key_usage_without_bits",
            filename = "caKeyUsageCrit.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

    @LintTest(
            name = "e_ext_key_usage_without_bits",
            filename = "caKeyUsageMissing.pem",
            expectedResultStatus = Status.NA)
    void testCase03() {
    }
}
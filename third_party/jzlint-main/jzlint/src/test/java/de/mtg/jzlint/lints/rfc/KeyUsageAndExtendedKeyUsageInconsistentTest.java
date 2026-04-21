package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class KeyUsageAndExtendedKeyUsageInconsistentTest {

    @LintTest(
            name = "e_key_usage_and_extended_key_usage_inconsistent",
            filename = "kuEkuInconsistent.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_key_usage_and_extended_key_usage_inconsistent",
            filename = "kuEkuConsistent.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

    @LintTest(
            name = "e_key_usage_and_extended_key_usage_inconsistent",
            filename = "kuEkuInconsistentMp.pem",
            expectedResultStatus = Status.ERROR)
    void testCase03() {
    }

    @LintTest(
            name = "e_key_usage_and_extended_key_usage_inconsistent",
            filename = "kuEkuConsistentMp.pem",
            expectedResultStatus = Status.PASS)
    void testCase04() {
    }

}

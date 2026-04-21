package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtKeyUsageNotCriticalTest {

    @LintTest(
            name = "w_ext_key_usage_not_critical",
            filename = "keyUsageNotCriticalSubCert.pem",
            expectedResultStatus = Status.WARN)
    void testCase01() {
    }

    @LintTest(
            name = "w_ext_key_usage_not_critical",
            filename = "caKeyUsageNotCrit.pem",
            expectedResultStatus = Status.WARN)
    void testCase02() {
    }

    @LintTest(
            name = "w_ext_key_usage_not_critical",
            filename = "domainValGoodSubject.pem",
            expectedResultStatus = Status.PASS)
    void testCase03() {
    }


    @LintTest(
            name = "w_ext_key_usage_not_critical",
            filename = "caKeyUsageCrit.pem",
            expectedResultStatus = Status.PASS)
    void testCase04() {
    }

    @LintTest(
            name = "w_ext_key_usage_not_critical",
            filename = "caKeyUsageMissing.pem",
            expectedResultStatus = Status.NA)
    void testCase05() {
    }


}
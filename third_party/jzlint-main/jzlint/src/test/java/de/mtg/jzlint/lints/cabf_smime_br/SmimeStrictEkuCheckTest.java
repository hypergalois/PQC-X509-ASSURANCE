package de.mtg.jzlint.lints.cabf_smime_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SmimeStrictEkuCheckTest {

    @LintTest(
            name = "e_smime_strict_eku_check",
            filename = "smime/mailboxValidatedStrictWithCommonName.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - mailbox validated, strict with EmailProtectionEKU")
    void testCase01() {
    }

    @LintTest(
            name = "e_smime_strict_eku_check",
            filename = "smime/domainValidatedWithEmailCommonName.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "na - certificate without mailbox validated policy")
    void testCase02() {
    }

    @LintTest(
            name = "e_smime_strict_eku_check",
            filename = "smime/mailboxValidatedLegacyWithCommonName.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "na - mailbox validated legacy certificate")
    void testCase03() {
    }

    @LintTest(
            name = "e_smime_strict_eku_check",
            filename = "smime/mailboxValidatedStrictMay2023.pem",
            expectedResultStatus = Status.NE,
            certificateDescription = "ne - certificate with NotBefore before effective date of lint")
    void testCase04() {
    }

    @LintTest(
            name = "e_smime_strict_eku_check",
            filename = "smime/individualValidatedStrictWithServerAuthEKU.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "error - certificate with extra EKU")
    void testCase05() {
    }

}
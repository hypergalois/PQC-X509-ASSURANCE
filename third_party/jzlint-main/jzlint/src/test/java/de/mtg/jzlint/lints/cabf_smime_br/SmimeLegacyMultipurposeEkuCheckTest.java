package de.mtg.jzlint.lints.cabf_smime_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SmimeLegacyMultipurposeEkuCheckTest {

    @LintTest(
            name = "e_smime_legacy_multipurpose_eku_check",
            filename = "smime/mailboxValidatedLegacyWithCommonName.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - mailbox validated, legacy with commonName")
    void testCase01() {
    }

    @LintTest(
            name = "e_smime_legacy_multipurpose_eku_check",
            filename = "smime/domainValidatedWithEmailCommonName.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "na - certificate without mailbox validated policy")
    void testCase02() {
    }

    @LintTest(
            name = "e_smime_legacy_multipurpose_eku_check",
            filename = "smime/mailboxValidatedLegacyWithCommonNameMay2023.pem",
            expectedResultStatus = Status.NE,
            certificateDescription = "ne - certificate with NotBefore before effective date of lint")
    void testCase03() {
    }

    @LintTest(
            name = "e_smime_legacy_multipurpose_eku_check",
            filename = "smime/mailboxValidatedLegacyWithoutEmailProtectionEKU.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "error - certificate without emailProtection EKU")
    void testCase04() {
    }

    @LintTest(
            name = "e_smime_legacy_multipurpose_eku_check",
            filename = "smime/organizationValidatedMultipurposeWithServerAuthEKU.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "error - certificate containing serverAuthEKU")
    void testCase05() {
    }

}
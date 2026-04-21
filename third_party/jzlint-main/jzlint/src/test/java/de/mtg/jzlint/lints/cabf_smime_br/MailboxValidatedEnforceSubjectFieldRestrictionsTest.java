package de.mtg.jzlint.lints.cabf_smime_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class MailboxValidatedEnforceSubjectFieldRestrictionsTest {

    @LintTest(
            name = "e_mailbox_validated_enforce_subject_field_restrictions",
            filename = "smime/mailboxValidatedLegacyWithCommonName.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - mailbox validated, legacy with commonName")
    void testCase01() {
    }

    @LintTest(
            name = "e_mailbox_validated_enforce_subject_field_restrictions",
            filename = "smime/mailboxValidatedMultipurposeWithCommonName.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - mailbox validated, multmailboxValidatedMultipurposeWithCommonNameipurpose with commonName")
    void testCase02() {
    }

    @LintTest(
            name = "e_mailbox_validated_enforce_subject_field_restrictions",
            filename = "smime/mailboxValidatedStrictWithCommonName.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - mailbox validated, strict with commonName")
    void testCase03() {
    }

    @LintTest(
            name = "e_mailbox_validated_enforce_subject_field_restrictions",
            filename = "smime/domainValidatedWithEmailCommonName.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "na - certificate without mailbox validated policy")
    void testCase04() {
    }

    @LintTest(
            name = "e_mailbox_validated_enforce_subject_field_restrictions",
            filename = "smime/mailboxValidatedLegacyWithCommonNameMay2023.pem",
            expectedResultStatus = Status.NE,
            certificateDescription = "ne - certificate with NotBefore before effective date of lint")
    void testCase05() {
    }

    @LintTest(
            name = "e_mailbox_validated_enforce_subject_field_restrictions",
            filename = "smime/mailboxValidatedLegacyWithCountryName.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "error - certificate with countryName",
            expectedResultDetails = "subject DN contains forbidden field: subject:countryName (2.5.4.6)")
    void testCase06() {
    }

    @LintTest(
            name = "e_mailbox_validated_enforce_subject_field_restrictions",
            filename = "smime/mailboxValidatedMultipurposeWithNonsenseSubjectField.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "error - certificate containing nonsense subject field (1.2.3.4.5.6.7.8.9.0)",
            expectedResultDetails = "subject DN contains forbidden field: 1.2.3.4.5.6.7.8.9.0")
    void testCase07() {
    }

}
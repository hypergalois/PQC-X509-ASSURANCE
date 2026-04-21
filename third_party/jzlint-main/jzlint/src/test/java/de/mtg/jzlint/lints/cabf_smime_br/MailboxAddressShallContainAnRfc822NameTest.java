package de.mtg.jzlint.lints.cabf_smime_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class MailboxAddressShallContainAnRfc822NameTest {

    @LintTest(
            name = "e_mailbox_address_shall_contain_an_rfc822_name",
            filename = "smime/MailboxAddressFromSAN/WithOtherNameMatched.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - subject:commonName email address matches san:otherName")
    void testCase01() {
    }

    @LintTest(
            name = "e_mailbox_address_shall_contain_an_rfc822_name",
            filename = "smime/MailboxAddressFromSAN/WithSANEmailMatched.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - subject:commonName email address matches san:emailAddress")
    void testCase02() {
    }

    @LintTest(
            name = "e_mailbox_address_shall_contain_an_rfc822_name",
            filename = "smime/MailboxAddressFromSAN/WithOnlySANEmail.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "na - only contains one san:emailAddress value")
    void testCase03() {
    }

    @LintTest(
            name = "e_mailbox_address_shall_contain_an_rfc822_name",
            filename = "smime/MailboxAddressFromSAN/WithOnlySANOtherName.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "na - only contains one san:otherName value")
    void testCase04() {
    }

    @LintTest(
            name = "e_mailbox_address_shall_contain_an_rfc822_name",
            filename = "smime/MailboxAddressFromSAN/NotEffective.pem",
            expectedResultStatus = Status.NE,
            certificateDescription = "NE - before effective date")
    void testCase05() {
    }

    @LintTest(
            name = "e_mailbox_address_shall_contain_an_rfc822_name",
            filename = "smime/MailboxAddressFromSAN/NotApplicable.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "NA - does not contain smime certificate policy")
    void testCase06() {
    }

    @LintTest(
            name = "e_mailbox_address_shall_contain_an_rfc822_name",
            filename = "smime/MailboxAddressFromSAN/WithOtherNameUnmatched.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "fail - subject:commonName email address does not match san:otherName")
    void testCase07() {
    }

    @LintTest(
            name = "e_mailbox_address_shall_contain_an_rfc822_name",
            filename = "smime/MailboxAddressFromSAN/WithOtherNameIncorrectType.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "fail - subject:commonName email address does not match the email value under san:otherName")
    void testCase08() {
    }

    @LintTest(
            name = "e_mailbox_address_shall_contain_an_rfc822_name",
            filename = "smime/MailboxAddressFromSAN/WithSANEmailUnmatched.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "fail - subject:commonName email address does not match san:emailAddress")
    void testCase09() {
    }

    @LintTest(
            name = "e_mailbox_address_shall_contain_an_rfc822_name",
            filename = "smime/MailboxAddressFromSAN/sponsorValidatedMultipurposeEmailInSubjectNotInSAN.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "fail - subject:commonName email address does not match san:emailAddress, certificate is sponsor validated")
    void testCase10() {
    }

    @LintTest(
            name = "e_mailbox_address_shall_contain_an_rfc822_name",
            filename = "smime/MailboxAddressFromSAN/sponsorValidatedMultipurposePersonalNameInCN.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "na - subject:commonName is personal name, san:emailAddress contains an email")
    void testCase11() {
    }

}
package de.mtg.jzlint.lints.cabf_smime_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class CommonnameMailboxValidatedTest {

    @LintTest(
            name = "e_commonname_mailbox_validated",
            filename = "smime/mailbox_validated_common_name_good_email.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - valid email in commonName")
    void testCase01() {
    }

    @LintTest(
            name = "e_commonname_mailbox_validated",
            filename = "smime/mailbox_validated_common_name_bad_email.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "fail - invalid email in commonName")
    void testCase02() {
    }

}
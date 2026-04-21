package de.mtg.jzlint.lints.cabf_smime_br;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(LintTestExtension.class)
class SingleEmailSubjectIfPresentTest {

    @LintTest(
            name = "e_single_email_subject_if_present",
            filename = "smime/twoEmailAddressesInSubjectDN.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "error - email address present in subjectDN with multiple values")
    void testCase01() {
    }

    @LintTest(
            name = "e_single_email_subject_if_present",
            filename = "smime/oneEmailAddressInSubjectDN.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - email address present in subjectDN with one value")
    void testCase02() {
    }

    @LintTest(
            name = "e_single_email_subject_if_present",
            filename = "smime/noEmailAddressInSubjectDN.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "na - no email address present in subjectDN")
    void testCase03() {
    }

}

package de.mtg.jzlint.lints.cabf_smime_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class StrictMultipurposeSmimeExtSubjectDirectoryAttrTest {
    
    @LintTest(
            name = "e_strict_multipurpose_smime_ext_subject_directory_attr",
            filename = "smime/mailboxValidatedStrictWithCommonName.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - no subject dir attributes extension")
    void testCase01() {
    }

    @LintTest(
            name = "e_strict_multipurpose_smime_ext_subject_directory_attr",
            filename = "smime/multipurposeWithSubjectDirectoryAttributes.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "error - multipurpose with subject dir attributes extension")
    void testCase02() {
    }

    @LintTest(
            name = "e_strict_multipurpose_smime_ext_subject_directory_attr",
            filename = "smime/ec_legacy_digital_signature_ku.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "NA - legacy no subject dir attributes extension")
    void testCase03() {
    }

}

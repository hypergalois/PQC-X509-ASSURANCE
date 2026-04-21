package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtSubjectKeyIdentifierMissingSubCertTest {

    @LintTest(
            name = "w_ext_subject_key_identifier_missing_sub_cert",
            filename = "subCertNoSKI.pem",
            expectedResultStatus = Status.WARN)
    void testCase01() {
    }

    @LintTest(
            name = "w_ext_subject_key_identifier_missing_sub_cert",
            filename = "orgValGoodAllFields.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}
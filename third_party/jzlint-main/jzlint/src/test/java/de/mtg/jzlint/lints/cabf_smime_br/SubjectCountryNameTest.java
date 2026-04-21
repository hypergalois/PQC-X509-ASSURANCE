package de.mtg.jzlint.lints.cabf_smime_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubjectCountryNameTest {

    @LintTest(
            name = "e_subject_country_name",
            filename = "smime/subject_country_name_valid.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - valid email in commonName")
    void testCase01() {
    }

    @LintTest(
            name = "e_subject_country_name",
            filename = "smime/subject_country_name_invalid.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "fail - invalid email in commonName")
    void testCase02() {
    }

}
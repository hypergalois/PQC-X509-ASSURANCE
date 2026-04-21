package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtraSubjectCommonNamesTest {

    @LintTest(
            name = "w_extra_subject_common_names",
            filename = "commonNamesURL.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "One subject common name")
    void testCase01() {
    }

    @LintTest(
            name = "w_extra_subject_common_names",
            filename = "extraCommonNames.pem",
            expectedResultStatus = Status.WARN,
            certificateDescription = "Multiple subject common names")
    void testCase02() {
    }

}
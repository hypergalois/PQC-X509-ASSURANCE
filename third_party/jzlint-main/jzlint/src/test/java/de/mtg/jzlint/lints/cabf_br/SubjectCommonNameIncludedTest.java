package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubjectCommonNameIncludedTest {

    @LintTest(
            name = "n_subject_common_name_included",
            filename = "commonNamesURL.pem",
            expectedResultStatus = Status.NOTICE)
    void testCase01() {
    }

    @LintTest(
            name = "n_subject_common_name_included",
            filename = "commonNamesGood.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}
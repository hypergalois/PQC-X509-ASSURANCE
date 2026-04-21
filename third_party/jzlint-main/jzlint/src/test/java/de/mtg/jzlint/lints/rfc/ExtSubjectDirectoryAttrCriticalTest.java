package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtSubjectDirectoryAttrCriticalTest {

    @LintTest(
            name = "e_ext_subject_directory_attr_critical",
            filename = "subDirAttCritical.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_subject_directory_attr_critical",
            filename = "RFC5280example2.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}
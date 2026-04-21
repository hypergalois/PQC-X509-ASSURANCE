package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubjectPrintableStringBadalphaTest {

    @LintTest(
            name = "e_subject_printable_string_badalpha",
            filename = "subjectCommonNameLengthGood.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "valid subj. PrintableStrings")
    void testCase01() {
    }

    @LintTest(
            name = "e_subject_printable_string_badalpha",
            filename = "subjectWithSingleQuote.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "valid subject with single quote")
    void testCase02() {
    }

    @LintTest(
            name = "e_subject_printable_string_badalpha",
            filename = "subjectCommonNamePrintableStringBadAlpha.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "invalid subj. CN PrintableString")
    void testCase03() {
    }
}
package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubjectDnNotPrintableCharactersTest {

    @LintTest(
            name = "e_subject_dn_not_printable_characters",
            filename = "orgValGoodAllFields.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_subject_dn_not_printable_characters",
            filename = "subjectDNNotPrintableCharsUTF8.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

    @LintTest(
            name = "e_subject_dn_not_printable_characters",
            filename = "subjectDNNotPrintableCharacters.pem",
            expectedResultStatus = Status.ERROR)
    void testCase03() {
    }

}
package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtSanNotCriticalWithoutSubjectTest {

    @LintTest(
            name = "e_ext_san_not_critical_without_subject",
            filename = "SANSubjectEmptyNotCritical.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_san_not_critical_without_subject",
            filename = "subCaEmptySubject.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

    @LintTest(
            name = "e_ext_san_not_critical_without_subject",
            filename = "SANCriticalSubjectUncommonOnly.pem",
            expectedResultStatus = Status.PASS)
    void testCase03() {
    }

}
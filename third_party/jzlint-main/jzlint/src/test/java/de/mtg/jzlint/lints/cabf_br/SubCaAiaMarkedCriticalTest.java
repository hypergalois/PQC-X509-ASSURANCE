package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubCaAiaMarkedCriticalTest {

    @LintTest(
            name = "e_sub_ca_aia_marked_critical",
            filename = "subCAAIAMarkedCritical.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_sub_ca_aia_marked_critical",
            filename = "subCAAIANotMarkedCritical.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}
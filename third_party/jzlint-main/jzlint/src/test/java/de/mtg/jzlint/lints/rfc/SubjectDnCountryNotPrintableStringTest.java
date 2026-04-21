package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubjectDnCountryNotPrintableStringTest {

    @LintTest(
            name = "e_subject_dn_country_not_printable_string",
            filename = "SubjectDNAndIssuerDNCountryPrintableString.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_subject_dn_country_not_printable_string",
            filename = "SubjectDNCountryNotPrintableString.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

}
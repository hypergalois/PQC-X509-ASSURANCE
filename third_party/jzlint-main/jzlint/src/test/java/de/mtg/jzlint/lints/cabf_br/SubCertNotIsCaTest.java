package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubCertNotIsCaTest {

    @LintTest(
            name = "e_sub_cert_not_is_ca",
            filename = "subCertIsNotCA.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_sub_cert_not_is_ca",
            filename = "subCertIsCA.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

}
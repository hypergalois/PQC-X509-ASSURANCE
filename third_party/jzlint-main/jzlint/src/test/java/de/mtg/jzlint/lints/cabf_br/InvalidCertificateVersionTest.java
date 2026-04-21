package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class InvalidCertificateVersionTest
{

    @LintTest(
            name = "e_invalid_certificate_version",
            filename = "certVersion2WithExtension.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_invalid_certificate_version",
            filename = "certVersion3NoExtensions.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}
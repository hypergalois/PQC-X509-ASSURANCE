package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class CertExtensionsVersionNot3Test {

    @LintTest(
            name = "e_cert_extensions_version_not_3",
            filename = "certVersion2WithExtension.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_cert_extensions_version_not_3",
            filename = "caBasicConstCrit.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

    @LintTest(
            name = "e_cert_extensions_version_not_3",
            filename = "certVersion2NoExtensions.pem",
            expectedResultStatus = Status.PASS)
    void testCase03() {
    }
}
package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class CertUniqueIdentifierVersionNot2Or3Test {

    @LintTest(
            name = "e_cert_unique_identifier_version_not_2_or_3",
            filename = "uniqueIdVersion3.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_cert_extensions_version_not_3",
            filename = "uniqueIdVersion1.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

}
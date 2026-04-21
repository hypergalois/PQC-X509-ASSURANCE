package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class CertContainsUniqueIdentifierTest {

    @LintTest(
            name = "e_cert_contains_unique_identifier",
            filename = "issuerUID.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_cert_contains_unique_identifier",
            filename = "subjectUID.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

    @LintTest(
            name = "e_cert_contains_unique_identifier",
            filename = "orgValGoodAllFields.pem",
            expectedResultStatus = Status.PASS)
    void testCase03() {
    }
}

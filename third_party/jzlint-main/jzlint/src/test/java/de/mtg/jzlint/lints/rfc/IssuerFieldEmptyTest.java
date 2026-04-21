package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class IssuerFieldEmptyTest {

    @LintTest(
            name = "e_issuer_field_empty",
            filename = "issuerFieldMissing.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_issuer_field_empty",
            filename = "issuerFieldFilled.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}
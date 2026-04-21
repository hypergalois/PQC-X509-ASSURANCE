package de.mtg.jzlint.lints.community;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class MultipleIssuerRdnTest {

    @LintTest(
            name = "w_multiple_issuer_rdn",
            filename = "issuerRDNTwoAttribute.pem",
            expectedResultStatus = Status.WARN)
    void testCase01() {
    }

    @LintTest(
            name = "w_multiple_issuer_rdn",
            filename = "RSASHA1Good.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}
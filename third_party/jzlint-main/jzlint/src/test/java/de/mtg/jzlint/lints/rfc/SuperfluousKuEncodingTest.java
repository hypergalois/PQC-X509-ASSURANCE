package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SuperfluousKuEncodingTest {

    @LintTest(
            name = "e_superfluous_ku_encoding",
            filename = "trustwaveP256CASuperfluousBytesOnKU.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Known Trustwave P256 with trailing zero byte in KU")
    void testCase01() {
    }

    @LintTest(
            name = "e_superfluous_ku_encoding",
            filename = "trustwaveP384CASuperfluousBytesOnKU.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Known Trustwave P384 with trailing zero byte in KU")
    void testCase02() {
    }

    @LintTest(
            name = "e_superfluous_ku_encoding",
            filename = "keyUsageWithoutTrailingZeroes.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "A cert with CertSign | CRLSign and no trailing zero byte")
    void testCase03() {
    }
}
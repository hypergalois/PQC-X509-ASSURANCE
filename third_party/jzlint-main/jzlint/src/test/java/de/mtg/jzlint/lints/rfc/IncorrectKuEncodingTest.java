package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class IncorrectKuEncodingTest {

    @LintTest(
            name = "e_incorrect_ku_encoding",
            filename = "incorrect_unused_bits_in_ku_encoding.pem",
            expectedResultStatus = Status.ERROR,
            expectedResultDetails = "declared to be 5, but it should be 7")
    void testCase01() {
    }

    @LintTest(
            name = "e_incorrect_ku_encoding",
            filename = "keyUsageCertSignEndEntity.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}
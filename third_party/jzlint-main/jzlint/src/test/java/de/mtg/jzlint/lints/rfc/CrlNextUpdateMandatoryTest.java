package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintCRLTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class CrlNextUpdateMandatoryTest {
    @LintCRLTest(
            name = "e_crl_has_next_update",
            filename = "crlHasNextUpdate.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintCRLTest(
            name = "e_crl_has_next_update",
            filename = "crlNotHaveNextUpdate.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }
}
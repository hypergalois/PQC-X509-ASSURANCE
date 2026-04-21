package de.mtg.jzlint.lints.mozilla;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class MpAuthorityKeyIdentifierCorrectTest {

    @LintTest(
            name = "e_mp_authority_key_identifier_correct",
            filename = "mpAuthorityKeyIdentifierIncorrect.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Authority key ID includes both the key ID and the issuer's name and serial")
    void testCase01() {
    }

    @LintTest(
            name = "e_mp_authority_key_identifier_correct",
            filename = "mpAuthorityKeyIdentifierCorrect.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Authority key ID includes the key ID")
    void testCase02() {
    }

}
package de.mtg.jzlint.lints.cabf_smime_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class AuthorityKeyIdentifierCorrectTest {

    @LintTest(
            name = "e_authority_key_identifier_correct",
            filename = "smime/authority_key_identifier_valid.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - cert has keyIdentifier")
    void testCase01() {
    }

    @LintTest(
            name = "e_authority_key_identifier_correct",
            filename = "smime/authority_key_identifier_invalid.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Error - cert has serial and DirName")
    void testCase02() {
    }

}

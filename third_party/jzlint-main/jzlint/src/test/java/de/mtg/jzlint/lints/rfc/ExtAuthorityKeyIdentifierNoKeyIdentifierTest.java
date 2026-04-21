package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtAuthorityKeyIdentifierNoKeyIdentifierTest {

    @LintTest(
            name = "e_ext_authority_key_identifier_no_key_identifier",
            filename = "akidNoKeyIdentifier.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_authority_key_identifier_no_key_identifier",
            filename = "akidWithKeyID.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}
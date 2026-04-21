package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class PublicKeyTypeNotAllowedTest {

    @LintTest(
            name = "e_public_key_type_not_allowed",
            filename = "unknownpublickey.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_public_key_type_not_allowed",
            filename = "rsawithsha1before2016.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

    @LintTest(
            name = "e_public_key_type_not_allowed",
            filename = "ecdsaP256.pem",
            expectedResultStatus = Status.PASS)
    void testCase03() {
    }
}
package de.mtg.jzlint.lints.mozilla;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class MpModulusMustBe2048BitsOrMoreTest {

    @LintTest(
            name = "e_mp_modulus_must_be_2048_bits_or_more",
            filename = "mpModulus1024.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Certificate with less than 2048 bit rsa key modulus length")
    void testCase01() {
    }

    @LintTest(
            name = "e_mp_modulus_must_be_2048_bits_or_more",
            filename = "mpModulus2048.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Certificate with rsa key modulus length equal to 2048")
    void testCase02() {
    }

}
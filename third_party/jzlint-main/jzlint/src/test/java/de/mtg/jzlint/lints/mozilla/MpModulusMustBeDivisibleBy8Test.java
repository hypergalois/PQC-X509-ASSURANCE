package de.mtg.jzlint.lints.mozilla;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class MpModulusMustBeDivisibleBy8Test {

    @LintTest(
            name = "e_mp_modulus_must_be_divisible_by_8",
            filename = "mpModulus4095.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Certificate with rsa key modulus length not divisible by 8")
    void testCase01() {
    }

    @LintTest(
            name = "e_mp_modulus_must_be_divisible_by_8",
            filename = "mpModulus2048.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Certificate with rsa key modulus length equal to 2048")
    void testCase02() {
    }

}
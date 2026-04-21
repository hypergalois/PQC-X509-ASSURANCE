package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubCertStreetAddressShouldNotExistTest {

    @LintTest(
            name = "e_sub_cert_street_address_should_not_exist",
            filename = "streetAddressCannotExist.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_sub_cert_street_address_should_not_exist",
            filename = "streetAddressCanExist.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}
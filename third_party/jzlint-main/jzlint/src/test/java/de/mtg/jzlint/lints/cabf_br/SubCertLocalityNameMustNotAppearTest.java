package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubCertLocalityNameMustNotAppearTest {

    @LintTest(
            name = "e_sub_cert_locality_name_must_not_appear",
            filename = "subCertLocalityNameProhibited.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_sub_cert_locality_name_must_not_appear",
            filename = "subCertLocalityNameNotProhibited.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}

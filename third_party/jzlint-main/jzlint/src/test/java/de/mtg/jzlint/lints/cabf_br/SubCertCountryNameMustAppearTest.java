package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubCertCountryNameMustAppearTest {

    @LintTest(
            name = "e_sub_cert_country_name_must_appear",
            filename = "subCertCountryNameMustAppear.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

}
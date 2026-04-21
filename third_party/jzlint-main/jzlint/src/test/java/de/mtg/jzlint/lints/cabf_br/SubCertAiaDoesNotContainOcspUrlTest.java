package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubCertAiaDoesNotContainOcspUrlTest {

    @LintTest(
            name = "e_sub_cert_aia_does_not_contain_ocsp_url",
            filename = "subCertWIssuerURL.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_sub_cert_aia_does_not_contain_ocsp_url",
            filename = "subCertWOcspURL.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}
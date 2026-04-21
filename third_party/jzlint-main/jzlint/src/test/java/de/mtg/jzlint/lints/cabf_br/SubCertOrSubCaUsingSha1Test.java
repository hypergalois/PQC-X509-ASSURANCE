package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubCertOrSubCaUsingSha1Test {

    @LintTest(
            name = "e_sub_cert_or_sub_ca_using_sha1",
            filename = "rsawithsha1after2016.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_sub_cert_or_sub_ca_using_sha1",
            filename = "rsawithsha1before2016.pem",
            expectedResultStatus = Status.NE)
    void testCase02() {
    }

}
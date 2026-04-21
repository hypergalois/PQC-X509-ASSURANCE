package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtSanUriNotIa5Test {

    @LintTest(
            name = "e_ext_san_uri_not_ia5",
            filename = "SANURIIA5.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_san_uri_not_ia5",
            filename = "SANURINotIA5.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

}
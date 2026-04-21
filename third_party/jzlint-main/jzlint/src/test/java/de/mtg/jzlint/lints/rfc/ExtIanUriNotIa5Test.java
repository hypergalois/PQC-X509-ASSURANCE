package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtIanUriNotIa5Test {

    @LintTest(
            name = "e_ext_ian_uri_not_ia5",
            filename = "IANURIIA5String.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_ian_uri_not_ia5",
            filename = "IANURINotIA5String.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }
}
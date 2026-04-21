package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtIanEmptyNameTest {

    @LintTest(
            name = "e_ext_ian_empty_name",
            filename = "IANEmptyName.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_ian_empty_name",
            filename = "IANDNSIA5String.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}
package de.mtg.jzlint.lints.community;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SanWildcardNotFirstTest {

    @LintTest(
            name = "e_san_wildcard_not_first",
            filename = "SANWildcardFirst.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_san_wildcard_not_first",
            filename = "SANURIValid.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}
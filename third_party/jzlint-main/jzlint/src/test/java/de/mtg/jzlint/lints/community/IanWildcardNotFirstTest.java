package de.mtg.jzlint.lints.community;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class IanWildcardNotFirstTest {

    @LintTest(
            name = "e_ian_wildcard_not_first",
            filename = "IANWildcardFirst.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_ian_wildcard_not_first",
            filename = "IANURIValid.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }
}
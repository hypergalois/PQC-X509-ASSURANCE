package de.mtg.jzlint.lints.community;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class IanIanaPubSuffixEmptyTest {

    @LintTest(
            name = "w_ian_iana_pub_suffix_empty",
            filename = "IANBareSuffix.pem",
            expectedResultStatus = Status.WARN)
    void testCase01() {
    }

    @LintTest(
            name = "w_ian_iana_pub_suffix_empty",
            filename = "IANGoodSuffix.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }
}
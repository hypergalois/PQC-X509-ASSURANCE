package de.mtg.jzlint.lints.community;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SanIanaPubSuffixEmptyTest {

    @LintTest(
            name = "n_san_iana_pub_suffix_empty",
            filename = "SANBareSuffix.pem",
            expectedResultStatus = Status.NOTICE)
    void testCase01() {
    }

    @LintTest(
            name = "n_san_iana_pub_suffix_empty",
            filename = "multiEmptyPubSuffix.pem",
            expectedResultStatus = Status.NOTICE)
    void testCase02() {
    }

    @LintTest(
            name = "n_san_iana_pub_suffix_empty",
            filename = "newlinesInTLD.pem",
            expectedResultStatus = Status.PASS)
    void testCase03() {
    }

    @LintTest(
            name = "n_san_iana_pub_suffix_empty",
            filename = "sanPrivatePublicSuffix.pem",
            expectedResultStatus = Status.PASS)
    void testCase04() {
    }

    @LintTest(
            name = "n_san_iana_pub_suffix_empty",
            filename = "SANGoodSuffix.pem",
            expectedResultStatus = Status.PASS)
    void testCase05() {
    }
}
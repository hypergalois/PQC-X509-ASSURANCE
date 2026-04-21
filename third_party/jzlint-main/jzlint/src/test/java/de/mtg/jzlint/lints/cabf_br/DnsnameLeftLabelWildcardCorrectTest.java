package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class DnsnameLeftLabelWildcardCorrectTest {

    @LintTest(
            name = "e_dnsname_left_label_wildcard_correct",
            filename = "dnsNameWildcardCorrect.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_dnsname_left_label_wildcard_correct",
            filename = "dnsNameWildcardIncorrect.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

}
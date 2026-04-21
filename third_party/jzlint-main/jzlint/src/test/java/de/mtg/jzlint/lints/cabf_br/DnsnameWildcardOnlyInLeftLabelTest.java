package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class DnsnameWildcardOnlyInLeftLabelTest {

    @LintTest(
            name = "e_dnsname_wildcard_only_in_left_label",
            filename = "dnsNameWildcardOnlyInLeftLabel.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_dnsname_wildcard_only_in_left_label",
            filename = "dnsNameWildcardNotOnlyInLeftLabel.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

}
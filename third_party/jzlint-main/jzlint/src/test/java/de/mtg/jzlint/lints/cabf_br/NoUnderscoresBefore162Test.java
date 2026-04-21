package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class NoUnderscoresBefore162Test {

    @LintTest(
            name = "e_no_underscores_before_1_6_2",
            filename = "dNSNameNoUnderscores.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "No underscores")
    void testCase01() {
    }

    @LintTest(
            name = "e_no_underscores_before_1_6_2",
            filename = "dNSNameWithUnderscores.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription =  "An underscores")
    void testCase02() {
    }

    @LintTest(
            name = "e_no_underscores_before_1_6_2",
            filename = "dNSNoUnderscoresNotEffectiveForCABF_1_6_2.pem",
            expectedResultStatus = Status.NE,
            certificateDescription = "After ineffective date / after Ballot 1.6.2")
    void testCase03() {
    }
}
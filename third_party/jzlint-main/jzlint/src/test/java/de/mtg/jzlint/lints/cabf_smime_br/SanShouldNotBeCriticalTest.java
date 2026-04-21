package de.mtg.jzlint.lints.cabf_smime_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SanShouldNotBeCriticalTest {

    @LintTest(
            name = "w_san_should_not_be_critical",
            filename = "smime/san_non_critical_non_empty_subject.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - certificate with non-critical SAN and non-empty subject")
    void testCase01() {
    }

    @LintTest(
            name = "w_san_should_not_be_critical",
            filename = "smime/san_critical_non_empty_subject.pem",
            expectedResultStatus = Status.WARN,
            certificateDescription = "warn - certificate with critical SAN and non-empty subject")
    void testCase02() {
    }

    @LintTest(
            name = "w_san_should_not_be_critical",
            filename = "ecdsaP224.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "na - certificate has no SMIME BR policy")
    void testCase03() {
    }

}

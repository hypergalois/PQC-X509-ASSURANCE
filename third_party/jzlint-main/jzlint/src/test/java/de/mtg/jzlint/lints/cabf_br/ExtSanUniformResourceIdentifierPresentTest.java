package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtSanUniformResourceIdentifierPresentTest {

    @LintTest(
            name = "e_ext_san_uniform_resource_identifier_present",
            filename = "SANCaGood.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_san_uniform_resource_identifier_present",
            filename = "SANURIBeginning.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

    @LintTest(
            name = "e_ext_san_uniform_resource_identifier_present",
            filename = "SANURIEnd.pem",
            expectedResultStatus = Status.ERROR)
    void testCase03() {
    }

}

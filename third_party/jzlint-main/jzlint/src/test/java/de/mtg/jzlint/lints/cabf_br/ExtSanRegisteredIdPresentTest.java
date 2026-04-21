package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtSanRegisteredIdPresentTest {

    @LintTest(
            name = "e_ext_san_registered_id_present",
            filename = "SANCaGood.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_san_registered_id_present",
            filename = "SANRegisteredIdBeginning.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

    @LintTest(
            name = "e_ext_san_registered_id_present",
            filename = "SANRegisteredIdEnd.pem",
            expectedResultStatus = Status.ERROR)
    void testCase03() {
    }

}
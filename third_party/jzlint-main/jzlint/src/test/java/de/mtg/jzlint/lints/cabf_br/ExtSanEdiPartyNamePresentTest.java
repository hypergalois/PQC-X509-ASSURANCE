package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtSanEdiPartyNamePresentTest {

    @LintTest(
            name = "e_ext_san_edi_party_name_present",
            filename = "SANEDIParty.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_san_edi_party_name_present",
            filename = "SANOtherName.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}
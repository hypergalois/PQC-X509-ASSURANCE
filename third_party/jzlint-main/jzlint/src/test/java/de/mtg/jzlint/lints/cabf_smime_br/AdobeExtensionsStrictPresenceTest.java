package de.mtg.jzlint.lints.cabf_smime_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class AdobeExtensionsStrictPresenceTest {

    @LintTest(
            name = "e_adobe_extensions_strict_presence",
            filename = "smime/mailboxValidatedStrictWithoutAdobeExtensions.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - cert without adobe extensions")
    void testCase01() {
    }

    @LintTest(
            name = "e_adobe_extensions_strict_presence",
            filename = "smime/domainValidatedWithEmailCommonName.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "NA - non-SMIME BR cert")
    void testCase02() {
    }

    @LintTest(
            name = "e_adobe_extensions_strict_presence",
            filename = "smime/mailboxValidatedLegacyWithCommonName.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "NA - non-strict SMIME BR cert")
    void testCase03() {
    }

    @LintTest(
            name = "e_adobe_extensions_strict_presence",
            filename = "smime/mailboxValidatedStrictMay2023.pem",
            expectedResultStatus = Status.NE,
            certificateDescription = "NE - certificate dated before effective date")
    void testCase04() {
    }

    @LintTest(
            name = "e_adobe_extensions_strict_presence",
            filename = "smime/organizationValidatedStrictWithAdobeTimeStampExtension.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Error - certificate with adobe time-stamp extension")
    void testCase05() {
    }

    @LintTest(
            name = "e_adobe_extensions_strict_presence",
            filename = "smime/sponsorValidatedStrictWithAdobeArchRevInfoExtension.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Error - certificate with adobe archive rev info extension")
    void testCase06() {
    }


}
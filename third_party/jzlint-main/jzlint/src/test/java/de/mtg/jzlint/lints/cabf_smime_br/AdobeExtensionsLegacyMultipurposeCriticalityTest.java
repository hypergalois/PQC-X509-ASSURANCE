package de.mtg.jzlint.lints.cabf_smime_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class AdobeExtensionsLegacyMultipurposeCriticalityTest {

    @LintTest(
            name = "e_adobe_extensions_legacy_multipurpose_criticality",
            filename = "smime/mailboxValidatedLegacyWithNonCriticalAdobeTimeStampExtension.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - mailbox legacy cert with non critical adobe time-stamp extension")
    void testCase01() {
    }

    @LintTest(
            name = "e_adobe_extensions_legacy_multipurpose_criticality",
            filename = "smime/organizationValidatedMultipurposeWithNonCriticalAdobeArchRevInfoExtension.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - organization multipurpose cert with non critical adobe archive rev info extension")
    void testCase02() {
    }

    @LintTest(
            name = "e_adobe_extensions_legacy_multipurpose_criticality",
            filename = "smime/domainValidatedWithEmailCommonName.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "NA - non-SMIME BR cert")
    void testCase03() {
    }

    @LintTest(
            name = "e_adobe_extensions_legacy_multipurpose_criticality",
            filename = "smime/organizationValidatedStrictWithAdobeTimeStampExtension.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "NA - non-legacy/multipurpose SMIME BR cert")
    void testCase04() {
    }

    @LintTest(
            name = "e_adobe_extensions_legacy_multipurpose_criticality",
            filename = "smime/organizationValidatedLegacyWithAdobeTimeStampExtensionMay2023.pem",
            expectedResultStatus = Status.NE,
            certificateDescription = "NE - certificate dated before effective date")
    void testCase05() {
    }

    @LintTest(
            name = "e_adobe_extensions_legacy_multipurpose_criticality",
            filename = "smime/sponsorValidatedMultipurposeWithCriticalAdobeTimeStampExtension.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Error - sponsor multipurpose certificate with adobe time-stamp extension marked as critical")
    void testCase06() {
    }

    @LintTest(
            name = "e_adobe_extensions_legacy_multipurpose_criticality",
            filename = "smime/individualValidatedLegacyWithCriticalAdobeArchRevInfoExtension.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Error - legacy certificate with adobe archive rev info extension marked as critical")
    void testCase07() {
    }

}
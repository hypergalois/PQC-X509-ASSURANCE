package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x509.Extension;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/************************************************
 CA Brower Forum Baseline Requirements, Section 7.1.2.2:
 f. nameConstraints (optional)
 If present, this extension SHOULD be marked critical*.
 * Non-critical Name Constraints are an exception to RFC 5280 (4.2.1.10), however, they MAY be used until the
 Name Constraints extension is supported by Application Software Suppliers whose software is used by a
 substantial portion of Relying Parties worldwide
 ************************************************/

@Lint(
        name = "w_sub_ca_name_constraints_not_critical",
        description = "Subordinate CA Certificate: NameConstraints if present, SHOULD be marked critical.",
        citation = "BRs: 7.1.2.2",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABV102Date)
public class SubCaNameConstraintsNotCritical implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        if (Utils.isExtensionCritical(certificate, Extension.nameConstraints.getId())) {
            return LintResult.of(Status.PASS);
        }
        return LintResult.of(Status.WARN);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubCA(certificate) && Utils.hasExtension(certificate, Extension.nameConstraints.getId());
    }

}

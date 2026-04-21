package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/************************************************************************************************************
 7.1.2.1. Root CA Certificate
 a. basicConstraints
 This extension MUST appear as a critical extension. The cA field MUST be set true. The pathLenConstraint field SHOULD NOT be present.
 ***********************************************************************************************************/

@Lint(
        name = "w_root_ca_basic_constraints_path_len_constraint_field_present",
        description = "Root CA certificate basicConstraint extension pathLenConstraint field SHOULD NOT be present",
        citation = "BRs: 7.1.2.1",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class RootCaBasicConstraintsPathLenConstraintFieldPresent implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawBasicConstraints = certificate.getExtensionValue(Extension.basicConstraints.getId());

        BasicConstraints basicConstraints = BasicConstraints.getInstance(ASN1OctetString.getInstance(rawBasicConstraints).getOctets());

        if (basicConstraints.getPathLenConstraint() != null) {
            return LintResult.of(Status.WARN);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isRootCA(certificate) && Utils.hasBasicConstraintsExtension(certificate);
    }

}

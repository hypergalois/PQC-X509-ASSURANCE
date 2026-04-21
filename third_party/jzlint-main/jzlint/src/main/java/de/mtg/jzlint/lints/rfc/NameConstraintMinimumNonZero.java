package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/************************************************************************
 RFC 5280: 4.2.1.10
 Within this profile, the minimum and maximum fields are not used with
 any name forms, thus, the minimum MUST be zero, and maximum MUST be
 absent.  However, if an application encounters a critical name
 constraints extension that specifies other values for minimum or
 maximum for a name form that appears in a subsequent certificate, the
 application MUST either process these fields or reject the
 certificate.
 ************************************************************************/

@Lint(
        name = "e_name_constraint_minimum_non_zero",
        description = "Within the name constraints name forms, the minimum field is not used and therefore MUST be zero",
        citation = "RFC 5280: 4.2.1.10",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class NameConstraintMinimumNonZero implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawNameConstraints = certificate.getExtensionValue(Extension.nameConstraints.getId());
        NameConstraints nameConstraints = NameConstraints.getInstance(ASN1OctetString.getInstance(rawNameConstraints).getOctets());

        GeneralSubtree[] excludedSubtrees = nameConstraints.getExcludedSubtrees();
        if (excludedSubtrees != null) {
            for (GeneralSubtree excludedSubtree : excludedSubtrees) {
                if (excludedSubtree.getMinimum() != null && excludedSubtree.getMinimum().intValue() != 0) {
                    return LintResult.of(Status.ERROR);
                }
            }
        }

        GeneralSubtree[] permittedSubtrees = nameConstraints.getPermittedSubtrees();
        if (permittedSubtrees != null) {
            for (GeneralSubtree permittedSubtree : permittedSubtrees) {
                if (permittedSubtree.getMinimum() != null && permittedSubtree.getMinimum().intValue() != 0) {
                    return LintResult.of(Status.ERROR);
                }
            }
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasExtension(certificate, Extension.nameConstraints.getId());
    }

}

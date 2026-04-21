package de.mtg.jzlint.lints.rfc;

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/********************************************************************
 The pathLenConstraint field is meaningful only if the cA boolean is
 asserted and the key usage extension, if present, asserts the
 keyCertSign bit (Section 4.2.1.3).  In this case, it gives the
 maximum number of non-self-issued intermediate certificates that may
 follow this certificate in a valid certification path.  (Note: The
 last certificate in the certification path is not an intermediate
 certificate, and is not included in this limit.  Usually, the last
 certificate is an end entity certificate, but it can be a CA
 certificate.)  A pathLenConstraint of zero indicates that no non-
 self-issued intermediate CA certificates may follow in a valid
 certification path.  Where it appears, the pathLenConstraint field
 MUST be greater than or equal to zero.  Where pathLenConstraint does
 not appear, no limit is imposed.
 ********************************************************************/

@Lint(
        name = "e_path_len_constraint_zero_or_less",
        description = "Where it appears, the pathLenConstraint field MUST be greater than or equal to zero",
        citation = "RFC 5280: 4.2.1.9",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class PathLenConstraintZeroOrLess implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawBasicConstraints = certificate.getExtensionValue(Extension.basicConstraints.getId());
        BasicConstraints basicConstraints = BasicConstraints.getInstance(ASN1OctetString.getInstance(rawBasicConstraints).getOctets());

        // TODO delete four lines if checkApplies changes
        ASN1Sequence basicConstraintsSeq = ASN1Sequence.getInstance(ASN1OctetString.getInstance(rawBasicConstraints).getOctets());
        if (basicConstraintsSeq.size() == 0) {
            return LintResult.of(Status.PASS);
        }

        if (basicConstraints.getPathLenConstraint() == null) {
            return LintResult.of(Status.PASS);
        }

        if (basicConstraints.getPathLenConstraint().compareTo(BigInteger.ZERO) == -1) {
            return LintResult.of(Status.ERROR);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {

        if (!Utils.hasBasicConstraintsExtension(certificate)) {
            return false;
        }

//        byte[] rawBasicConstraints = certificate.getExtensionValue(Extension.basicConstraints.getId());
//        ASN1Sequence basicConstraints = ASN1Sequence.getInstance(ASN1OctetString.getInstance(rawBasicConstraints).getOctets());
//
//        if (basicConstraints.size() == 0) {
//            return false;
//        }
//
//        if (basicConstraints.size() == 1) {
//            return basicConstraints.getObjectAt(0) instanceof ASN1Integer;
//        }

        return true;
    }


    // TODO this should be the proper implementation?
//    @Override
//    public boolean checkApplies(X509Certificate certificate) {
//
//        if (!Util.hasBasicConstraintsExtension(certificate)) {
//            return false;
//        }
//
//        byte[] rawBasicConstraints = certificate.getExtensionValue(Extension.basicConstraints.getId());
//        ASN1Sequence basicConstraints = ASN1Sequence.getInstance(ASN1OctetString.getInstance(rawBasicConstraints).getOctets());
//
//        if (basicConstraints.size() == 0) {
//            return false;
//        }
//
//        if (basicConstraints.size() == 1) {
//            return basicConstraints.getObjectAt(0) instanceof ASN1Integer;
//        }
//
//        return true;
//    }
}

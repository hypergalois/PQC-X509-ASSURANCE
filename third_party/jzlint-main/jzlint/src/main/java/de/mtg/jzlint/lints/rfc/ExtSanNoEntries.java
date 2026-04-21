package de.mtg.jzlint.lints.rfc;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;


/**********************************************************************
 RFC 5280: 4.2.1.6
 If the subjectAltName extension is present, the sequence MUST contain
 at least one entry.  Unlike the subject field, conforming CAs MUST
 NOT issue certificates with subjectAltNames containing empty
 GeneralName fields.  For example, an rfc822Name is represented as an
 IA5String.  While an empty string is a valid IA5String, such an
 rfc822Name is not permitted by this profile.  The behavior of clients
 that encounter such a certificate when processing a certification
 path is not defined by this profile.
 ***********************************************************************/

@Lint(
        name = "e_ext_san_no_entries",
        description = "If present, the SAN extension MUST contain at least one entry",
        citation = "RFC 5280: 4.2.1.6",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class ExtSanNoEntries implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawSAN = certificate.getExtensionValue(Extension.subjectAlternativeName.getId());

        try {
            List<GeneralName> allGeneralNames = Utils.getAllGeneralNames(rawSAN);

            if (allGeneralNames == null || allGeneralNames.isEmpty()) {
                return LintResult.of(Status.ERROR);
            }
        } catch (IOException ex) {
            return LintResult.of(Status.FATAL);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasExtension(certificate, Extension.subjectAlternativeName.getId());
    }
}

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


/************************************************
 When the issuerAltName extension contains a URI, the name MUST be
 stored in the uniformResourceIdentifier (an IA5String).
 ************************************************/


@Lint(
        name = "e_ext_ian_uri_not_ia5",
        description = "When issuer alternative name contains a URI, the name MUST be an IA5 string",
        citation = "RFC 5280: 4.2.1.7",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC5280)
public class ExtIanUriNotIa5 implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawIAN = certificate.getExtensionValue(Extension.issuerAlternativeName.getId());
        try {
            List<GeneralName> uris = Utils.getUniformResourceIdentifiers(rawIAN);
            return ExtSanUriNotIa5.isGeneralNameNotIa5(uris);
        } catch (IOException ex) {
            return LintResult.of(Status.FATAL);
        }
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasExtension(certificate, Extension.issuerAlternativeName.getId());
    }
}

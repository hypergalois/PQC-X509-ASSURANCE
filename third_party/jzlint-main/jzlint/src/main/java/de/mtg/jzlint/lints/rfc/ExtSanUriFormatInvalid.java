package de.mtg.jzlint.lints.rfc;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
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
 The name MUST include both a
 scheme (e.g., "http" or "ftp") and a scheme-specific-part.
 ************************************************/

@Lint(
        name = "e_ext_san_uri_format_invalid",
        description = "URIs in SAN extension must have a scheme and scheme specific part",
        citation = "RFC 5280: 4.2.1.6",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC5280)
public class ExtSanUriFormatInvalid implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawSAN = certificate.getExtensionValue(Extension.subjectAlternativeName.getId());

        try {
            List<GeneralName> uris = Utils.getUniformResourceIdentifiers(rawSAN);

            for (GeneralName generalName : uris) {
                String uriString = generalName.getName().toString();

                try {
                    URI uri = new URI(uriString);
                    if (uri.getScheme() == null) {
                        return LintResult.of(Status.ERROR);
                    }
                    if (uri.getHost() == null && uri.getRawUserInfo() == null && uri.isOpaque() && uri.getRawPath() == null) {
                        return LintResult.of(Status.ERROR);
                    }
                } catch (URISyntaxException ex) {
                    return LintResult.of(Status.ERROR);
                }
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

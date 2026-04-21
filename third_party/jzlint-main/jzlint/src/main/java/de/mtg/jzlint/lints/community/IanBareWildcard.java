package de.mtg.jzlint.lints.community;

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


@Lint(
        name = "e_ian_bare_wildcard",
        description = "A wildcard MUST be accompanied by other data to its right (Only checks IANDNSNames)",
        citation = "awslabs certlint",
        source = Source.COMMUNITY,
        effectiveDate = EffectiveDate.ZERO)
public class IanBareWildcard implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawIAN = certificate.getExtensionValue(Extension.issuerAlternativeName.getId());
        try {
            List<GeneralName> dnsNames = Utils.getDNSNames(rawIAN);
            for (GeneralName generalName : dnsNames) {
                String dnsName = generalName.getName().toString();
                if (dnsName.endsWith("*")) {
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
        return Utils.hasExtension(certificate, Extension.issuerAlternativeName.getId());
    }

}

package de.mtg.jlintissuer;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import de.mtg.jzlint.LintResult;

public interface JavaCRLIssuerLint {

    LintResult execute(X509CRL crl, X509Certificate issuerCertificate);

    boolean checkApplies(X509CRL crl, X509Certificate issuerCertificate);

}

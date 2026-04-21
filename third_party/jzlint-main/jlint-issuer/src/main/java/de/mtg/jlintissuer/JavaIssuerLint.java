package de.mtg.jlintissuer;

import java.security.cert.X509Certificate;

import de.mtg.jzlint.LintResult;

public interface JavaIssuerLint {

    LintResult execute(X509Certificate certificate, X509Certificate issuerCertificate);

    boolean checkApplies(X509Certificate certificate, X509Certificate issuerCertificate);
}



package de.mtg.jzlint.server;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.concurrent.ForkJoinPool;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.async.DeferredResult;

import de.mtg.jzlint.LintJSONResults;
import de.mtg.jzlint.utils.ParsedDomainNameUtils;

@RestController
public class LintController {

    @Value("${request.timeout:15000}")
    private long requestTimeout;

    @PostMapping(value = "/certificate/lint", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public DeferredResult<ResponseEntity<?>> lintCertificate(@RequestBody TBLCertificate tblCertificate) {
        DeferredResult<ResponseEntity<?>> response = new DeferredResult<>(requestTimeout, new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR));

        ForkJoinPool.commonPool().submit(() -> {
            try {
                byte[] rawPKIObject = tblCertificate.getCertificate().getBytes(StandardCharsets.US_ASCII);
                LintJSONResults lint = ServerUtils.lint(rawPKIObject, null, tblCertificate.getIncludeNames(), tblCertificate.getIncludeSources(), tblCertificate.getExcludeNames(), tblCertificate.getExcludeSources());
                X509Certificate certificate = ServerUtils.getCertificate(rawPKIObject);
                ParsedDomainNameUtils.cleanCacheEntry(certificate);
                response.setResult(new ResponseEntity<>(ServerUtils.convertResultToResponse(lint), HttpStatus.OK));
            } catch (Exception ex) {
                response.setResult(new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR));
            }
        });

        return response;
    }

    @PostMapping("/crl/lint")
    DeferredResult<ResponseEntity<?>> lintCRL(@RequestBody TBLCRL tblCrl) {
        DeferredResult<ResponseEntity<?>> response = new DeferredResult<>(requestTimeout, new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR));

        ForkJoinPool.commonPool().submit(() -> {
            try {
                byte[] rawPKIObject = tblCrl.getCrl().getBytes(StandardCharsets.US_ASCII);
                LintJSONResults lint = ServerUtils.lint(rawPKIObject, null, tblCrl.getIncludeNames(), tblCrl.getIncludeSources(), tblCrl.getExcludeNames(), tblCrl.getExcludeSources());
                response.setResult(new ResponseEntity<>(ServerUtils.convertResultToResponse(lint), HttpStatus.OK));
            } catch (Exception ex) {
                response.setResult(new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR));
            }
        });

        return response;
    }

    @PostMapping("/ocspresponse/lint")
    DeferredResult<ResponseEntity<?>> lintOCSP(@RequestBody TBLOCPResponse tblocpResponse) {
        DeferredResult<ResponseEntity<?>> response = new DeferredResult<>(requestTimeout, new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR));

        ForkJoinPool.commonPool().submit(() -> {
            try {
                byte[] rawPKIObject = tblocpResponse.getOcspResponse().getBytes(StandardCharsets.US_ASCII);
                LintJSONResults lint = ServerUtils.lint(rawPKIObject, null, tblocpResponse.getIncludeNames(), tblocpResponse.getIncludeSources(), tblocpResponse.getExcludeNames(), tblocpResponse.getExcludeSources());
                response.setResult(new ResponseEntity<>(ServerUtils.convertResultToResponse(lint), HttpStatus.OK));
            } catch (Exception ex) {
                response.setResult(new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR));
            }
        });

        return response;
    }

}

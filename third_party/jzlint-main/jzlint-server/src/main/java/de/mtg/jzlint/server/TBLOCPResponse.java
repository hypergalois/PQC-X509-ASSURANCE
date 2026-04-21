package de.mtg.jzlint.server;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class TBLOCPResponse {

    private String ocspResponse;

    private List<String> includeNames;
    private List<String> includeSources;
    private List<String> excludeSources;
    private List<String> excludeNames;


    public TBLOCPResponse() {
        // empty
    }

    public String getOcspResponse() {
        return ocspResponse;
    }

    public void setOcspResponse(String ocspResponse) {
        this.ocspResponse = ocspResponse;
    }

    public List<String> getIncludeNames() {
        return includeNames;
    }

    public void setIncludeNames(List<String> includeNames) {
        this.includeNames = includeNames;
    }

    public List<String> getIncludeSources() {
        return includeSources;
    }

    public void setIncludeSources(List<String> includeSources) {
        this.includeSources = includeSources;
    }

    public List<String> getExcludeSources() {
        return excludeSources;
    }

    public void setExcludeSources(List<String> excludeSources) {
        this.excludeSources = excludeSources;
    }

    public List<String> getExcludeNames() {
        return excludeNames;
    }

    public void setExcludeNames(List<String> excludeNames) {
        this.excludeNames = excludeNames;
    }

}

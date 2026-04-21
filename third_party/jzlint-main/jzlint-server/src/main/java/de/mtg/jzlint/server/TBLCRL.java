package de.mtg.jzlint.server;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class TBLCRL {

    private String crl;

    private List<String> includeNames;
    private List<String> includeSources;
    private List<String> excludeSources;
    private List<String> excludeNames;


    public TBLCRL() {
        // empty
    }

    public String getCrl() {
        return crl;
    }

    public void setCrl(String crl) {
        this.crl = crl;
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

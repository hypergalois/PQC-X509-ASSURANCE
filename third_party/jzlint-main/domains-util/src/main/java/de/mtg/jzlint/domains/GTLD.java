package de.mtg.jzlint.domains;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class GTLD {

    String delegationDate;
    String gTLD;
    String removalDate;

    public GTLD() {
        // empty
    }

    public String getDelegationDate() {
        return delegationDate;
    }

    public void setDelegationDate(String delegationDate) {
        this.delegationDate = delegationDate;
    }

    public String getgTLD() {
        return gTLD;
    }

    public void setgTLD(String gTLD) {
        this.gTLD = gTLD;
    }

    public String getRemovalDate() {
        return removalDate;
    }

    public void setRemovalDate(String removalDate) {
        this.removalDate = removalDate;
    }

}

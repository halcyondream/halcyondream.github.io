'use strict';


const FEED_ENDPOINT = 'https://services.nvd.nist.gov/rest/json/cves/1.0/?';


/**
 * Prepare a date for the format required by the NVD API.
 */
class DateParam extends Date {
    
    /**
     * Set the day as the previous day instead of the current
     * time.
     */
    setPreviousDate() {
        this.setHours(0, 0, 0, 0);
        this.setDate(this.getDate() - 2);
    }

    /**
     * Return a representation of the date in the format that
     * the NVD API will accept.
     * 
     * @returns `String`, the date in a modified ISO-string 
     * foramt.
     */
    toNvdDate() {

        const TZ_PATTERN = /(\.[0-9]{3}Z){1}$/;
        const TZ = ":000%20UTC-00:00";
        
        return this.toISOString().replace(TZ_PATTERN, TZ);
    }
}


/**
 * Return the full string with parameters. Note that a `fetch` request will
 * fail if you pass parameters with URL-encoding. This is likely a quirk 
 * with the NVD API itself.
 * 
 * @returns `String`, the URL with non-URL-encoded parameters.
 */
function _getParameterizedEndpoint() {

    const startDate = new DateParam();
    const endDate = new DateParam();

    startDate.setPreviousDate();

    console.log(startDate);
    console.log(endDate);

    // Decode the query parameters or the request will fail.
    return FEED_ENDPOINT + decodeURIComponent(
        new URLSearchParams({
            "pubStartDate"   : startDate.toNvdDate(),
            "pubEndDate"     : endDate.toNvdDate(),
            "addOns"         : "dictionaryCpes",
            "resultsPerPage" : 50
        })
    );
}


/**
 * Make a GET request to the API endpoint. Return a promise that contains 
 * the JSON dump, with all the vulnerability information.
 * 
 * @returns `Promise`, the results of the API call (contains a JSON).
 */
async function _fetchNvdJsonPromise(){
    const response = await fetch(_getParameterizedEndpoint());    
    return response.json();
}


/*
 * Add functionality to the String prototype to allow HTML sanitizing.
 *  https://www.delftstack.com/howto/javascript/encode-html-entities-in-javascript/
 */
String.prototype.htmlEncode = function() {

    return this.replace(/./gm, function(s) {

        // return "&#" + s.charCodeAt(0) + ";";
        return (s.match(/[a-z0-9\s]+/i)) ? s : "&#" + s.charCodeAt(0) + ";";
    });
};


// Assume an interface called CveProperty...


class CvePropertyText {
    
    constructor(name, value) {
        this._name = String(name)
        this._value = String(value);
    }

    getValue(encoded=true) {
        return encoded ? this._value.htmlEncode() : this._value;
    }

    asInnerHtml() {
        return  "<strong>" + this._name.htmlEncode() + "</strong>:&nbsp;"
            + this._value.htmlEncode() 
    }
}


class CvePropertyUrl extends CvePropertyText {

    asInnerHtml() {
        return "<strong>" + this._name.htmlEncode() + "</strong>:&nbsp;"
            + "<a href=\"" + this._value + "\" target=\"_blank\">"
            + this._value.htmlEncode()
            + "</a>"
    }
}


/**
 * Encapsulate CVE data.
 */
class CVE {

    constructor(json) {
        this.id = new CvePropertyText("CVE ID", json.cve.CVE_data_meta.ID);
        this.description = new CvePropertyText(
            "Description", json.cve.description.description_data[0].value
        );
        this.url = new CvePropertyUrl(
            "URL", json.cve.references.reference_data[0].url
        );
        this.publishedDate = new CvePropertyText(
            "Published Date", json.publishedDate
        );
        this.lastModifiedDate = new CvePropertyText(
            "Last Modified Date", json.lastModifiedDate
        );
    }

    /**
     * Get the CVE ID.
     * 
     * @param {boolean} encoded True if you want to apply HTML encoding
     * @returns `String`, the encoded or plain value.
     */
    getId(encoded=true) {
        return this.id.getValue(encoded);
    }

    print() {
        console.log("CVE ID: " + this.id);
    }

    asList() {
        return [
            this.description,
            this.url,
            this.publishedDate,
            this.lastModifiedDate
        ]
    }
}


/**
 * Write the objects to the DOM.
 * 
 * TODO: Find a sensible way to get the severities. May require a fetch 
 * rewrite (ex: using an alternative to the public API calls), or extra 
 * API calls for each specific object. Better solution is to see if it
 * does exist for the current API but is undocumented or 
 * underdocumented.
 * 
 * TODO: Break out the logic and wrap it together.
 */
async function writeFeedToDom() {

    let pageNode = document.createElement("div");
    pageNode.classList.add("page-content");

    let headerNode = document.createElement("div");
    headerNode.classList.add("header-container");

    let titleNode = document.createElement("div");
    titleNode.classList.add("header-child");
    titleNode.innerHTML = "<h1>Daily NIST NVD Parser</h1>";

    let dateNodeContainer = document.createElement("div");
    dateNodeContainer.classList.add("header-child");
    let dateNode = document.createElement("p");
    let date = new Date();
    dateNode.innerHTML = date.toDateString().htmlEncode();
    dateNodeContainer.append(dateNode);
    
    headerNode.append(titleNode);
    headerNode.append(dateNodeContainer);

    pageNode.append(headerNode);

    const json = await _fetchNvdJsonPromise();

    let cveWrapper = null;
    
    let vulnDivNode = null;
    let vulnDataNode = null;
    let vulnTitleNode = null;
    let vulnTitleLinkNode = null;
    
    for (let n of json.result.CVE_Items) {
        
        //console.log(n);
        cveWrapper = new CVE(n);

        vulnDivNode = document.createElement("div");
        vulnDivNode.classList.add("vuln-container");

        // Make a link to the CVE in the NIST website.
        vulnTitleLinkNode = document.createElement("a");

        vulnTitleLinkNode.href = 
            "https://nvd.nist.gov/vuln/detail/" 
            + encodeURIComponent(cveWrapper.getId(false));

        vulnTitleLinkNode.target = "_blank";
        
        vulnTitleLinkNode.innerHTML = cveWrapper.getId();

        // Then, make that link the section header.
        vulnTitleNode = document.createElement("h2")
        vulnTitleLinkNode.classList.add("vuln-title")
        vulnTitleNode.append(vulnTitleLinkNode);
        vulnDivNode.append(vulnTitleNode);

        // Append all details about the CVE to the CVE's DIV.
        for (const cveProperty of cveWrapper.asList()) {
            vulnDataNode = document.createElement("p");
            vulnDataNode.classList.add("vuln-data");
            vulnDataNode.innerHTML = cveProperty.asInnerHtml()
            vulnDivNode.append(vulnDataNode);
        }
        pageNode.append(vulnDivNode);
    }

    document.body.append(pageNode);
}
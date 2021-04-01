import requests,json,sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#https://services.nvd.nist.gov/rest/json/cve/1.0/CVE-2015-5611
#https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=cherokee

#url = https://services.nvd.nist.gov
#format = /rest/json
#type = /cve OR /cves
#version = /1.0
#search = /CVE-2015-5611 OR ?keyword=cherokee

API_URL = "https://services.nvd.nist.gov"
API_FORMAT = "rest/json"
API_VERSION = "1.0"

class Nvd:
    def __init__(self):
        self.test = 'NVD Test!'
        self.url = API_URL #https://services.nvd.nist.gov
        self.format = API_FORMAT #rest/json
        self.type = "cve"
        self.version = API_VERSION #1.0

    def call(self, search="", getdata={}):
        #CVE-2015-5611 OR ?keyword=cherokee
        response = ""
        try:
            if search[0:3].upper() != "CVE":
                getdata['keyword'] = search
                search=""
                self.type = "cves"

            response = requests.request("GET",self.url+'/'+self.format+"/"+self.type+"/"+self.version+"/"+search, params=getdata, verify=False)
            print(response.request.url)
            return response.json()
        except:
            print(self.test)
            return response

newnvd = Nvd()
#data = Nvd.call(newnvd,search="CVE-2020-25705")
nvd_params = {}
nvd_params['pubStartDate'] = '2021-03-31T00:00:00:000 UTC-05:00'
nvd_params['startIndex'] = 0
nvd_params['resultsPerPage'] = 2 #max allowed is 5000

data = Nvd.call(newnvd,getdata=nvd_params)
#data = Nvd.call(newnvd,search="CVE-2021-26855")
#data = Nvd.call(newnvd,search="Cherokee")

print(data)
#for cve in data['result']['CVE_Items']:
#    print(cve['cve']['CVE_data_meta']['ID'])

#CPE --> cpe:<cpe_version>:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>

#WHAT DO I WANT THIS TO DO

#Pull vulnerability data from NVD from a PREDEFINED WINDOW
#Run continuously
#Pull in asset inventory
#Match vuln intelligence from NVD with a known asset inventory to see if there are any matches
#Prioritize matches using NVD metadata (CVSS)



#vuln-intelligence-sources
    #NVD
#inventory-sources
    #Tenable
    #raw-json
#db-backends
    #in-memory
    #mongo
#vuln-record
    #CVE
    #CPE
    #CVSS (base, temp, env)
    #Meta
        #urls, and other stuff

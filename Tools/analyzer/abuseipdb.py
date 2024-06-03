import requests
from class_base import analyzer_base



class abuseip_api(analyzer_base):
    """
    This class will search on https://www.abuseipdb.com/ the ips reported utilizing the API.
    """

    def __init__(self, API="API"):
        self.endpoint = "https://api.abuseipdb.com/api/v2/check"
        self.header = {
                'Accept': 'application/json',
                'Key': API
                    } 
        self.ips_data = []
    
    def search(self, ip_list):
        """
        This function will search on https://www.abuseipdb.com/ the datas from each ips passed as argument utilizing the API and save some important datas returned.
        """

        for ip in ip_list:
            def query(function):
                    print(ip)
                    query = {
                    'ipAddress': ip,
                    'maxAgeInDays': '90'
                    }
                

                    req = requests.get(url=self.endpoint, headers=self.header, params=query)

                    data = req.json()
                    function(data)
            
            @query
            def abuseip_datas(*args):
                infos = {}
                data = args[0]['data']
                
                infos["Ip address"] = data["ipAddress"]
                infos["is white listed"] = data["isWhitelisted"]
                infos["abuse Confidence Score"] = data["abuseConfidenceScore"]
                infos["country Code"] = data["countryCode"]
                infos["usage Type"] = data["usageType"]
                infos["isp"] = data["isp"]
                infos["domain"] = data["domain"]
                infos["is Tor"] = data["isTor"]
                infos["total Reports"] = data["totalReports"]
                infos["num Distinct Users"] = data["numDistinctUsers"]
        
                self.ips_data.append(infos)

        return self.ips_data
            
                



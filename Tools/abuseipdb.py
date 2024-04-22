import requests


class abuseip_api:
    """
    This class will search on https://www.abuseipdb.com/ the ips reported utilizing the API.
    """
    def __init__(self, API:str):

        self.endpoint = "https://api.abuseipdb.com/api/v2/check"
        self.header = {
                'Accept': 'application/json',
                'Key': API
                        } 
        
    def search(self, ip_list):
        """
        This function will search on https://www.abuseipdb.com/ the datas from each ips passed as argument utilizing the API and save some important datas returned.
        """

        ips_data = []

        for ip in ip_list:
            infos = {}

            query = {
            'ipAddress': ip,
            'maxAgeInDays': '90'
            }

            req = requests.get(url=self.endpoint, headers=self.header, params=query)
            data = req.json()
            data = data['data']


            infos["Ip address"] = ip
            infos["is white listed"] = data["isWhitelisted"]
            infos["abuse Confidence Score"] = data["abuseConfidenceScore"]
            infos["country Code"] = data["countryCode"]
            infos["usage Type"] = data["usageType"]
            infos["isp"] = data["isp"]
            infos["domain"] = data["domain"]
            infos["is Tor"] = data["isTor"]
            infos["total Reports"] = data["totalReports"]
            infos["num Distinct Users"] = data["numDistinctUsers"]
            
    
            ips_data.append(infos)


        return ips_data

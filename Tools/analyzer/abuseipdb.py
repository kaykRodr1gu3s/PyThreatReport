import requests
from dotenv import load_dotenv
from os import getenv

from Tools.analyzer.class_base import analyzer_base



class Abuseip_Api(analyzer_base):
    """
    This class will search on https://www.abuseipdb.com/ the ips reported utilizing the API.
    """

    def __init__(self):
        load_dotenv()
        self.endpoint = "https://api.abuseipdb.com/api/v2/check"
        self.header = {
                'Accept': 'application/json',
                'Key': getenv("abuseipdb_api")
                    } 
        self.ips_content = {}
    
    def search(self, ip_list: list):
        """
        This function will search on https://www.abuseipdb.com/ the datas from each ips passed as argument utilizing the API and save some important datas returned.
        """

        for ip in ip_list:
            def query(func) -> list:
                    """
                    This decorator will request and parse the datas in a attribute and append to a list for return 


                    output >>> list
                    """
                    
                    queries = {
                    'ipAddress': ip,
                    'maxAgeInDays': '90'
                    }
                
                    req = requests.get(url=self.endpoint, headers=self.header, params=queries).json()
                    dict_datas = {key:req["data"][key] for key in func()}
                    self.ips_content[ip] = dict_datas

            @query
            def dict_keys():
                keys = ["ipAddress", "isWhitelisted", "abuseConfidenceScore", "countryCode", "usageType", "isp", "domain", "isTor", "totalReports", "numDistinctUsers"]
                return keys
               
        return self.ips_content
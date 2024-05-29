import pymisp


import Tools.analyzer.abuseipdb as abuseipdb
from class_base import Datas
import Tools.Datas.ips as serpro_ips



class Ips(Datas):
    def __init__(self, datas):
        self.datas = datas



class Misp:
    def __init__(self, misp_API: str):

        self.misp_endpoint = "https://localhost"
        self.misp_api = misp_API
        self.misp_verify_cert = False


    def misp_event_creator(self, ips_datas):
        """
        This function will upload the datas to the misp utilizng the API.

        """

        misp = pymisp.ExpandedPyMISP(self.misp_endpoint, self.misp_api, self.misp_verify_cert)
        event = pymisp.MISPEvent()

        event.info = "Observed Malicious IP Activity"
        event.analysis = "2"
        event.threat_level_id = "1"
        event.distribution = "3"
        event.add_tag('tlp:green')
        
        for key, ip in enumerate(ips_datas):
            ip_datas = ips_datas[key]
            print(ip_datas['Ip address'])

            event.add_attribute("ip-dst", ip, comment=f"Ip: {ip_datas['Ip address']}\nDomain: {ip_datas['domain']}\nCountry Code: {ip_datas['country Code']}\nInternet service provider: {ip_datas['isp']}\nUsage type: {ip_datas['usage Type']}\n\nis white listed: {ip_datas['is white listed']}\nabuse Confidence Score: {ip_datas['abuse Confidence Score']}\nis tor: {ip_datas['is Tor']}\ntotal reports: {ip_datas['total Reports']}\nnum Distinct Users: {ip_datas['num Distinct Users']}", disable_correlation=False)
            

        event.published = True
        misp.add_event(event)

 
ips = Ips(serpro_ips.serpro_ip_tracker.ip_tracker())

abuseip = abuseipdb.abuseip_api()
abuseip.search(ips.datas)

misp = Misp("MISP API")
misp.misp_event_creator(abuseip.search(ips.datas))
from pymisp import ExpandedPyMISP, MISPEvent

import Tools.analyzer.abuseipdb as abuseipdb
from class_base import Datas
import Tools.Datas.ips as ip_list


class Ips(Datas):
    def __init__(self, datas):
        self.datas = datas


class Hashes(Datas):
    def __init__(self, datas):
        self.datas = datas


class Misp:
    def __init__(self, misp_API: str):

        self.misp_endpoint = "https://localhost"
        self.misp_api = misp_API
        self.misp_verify_cert = False


    def misp_event_creator_IPS(self, ips_datas):
        """
        This function will upload the datas to the MISP using the API.
        """

        misp = ExpandedPyMISP(self.misp_endpoint, self.misp_api, self.misp_verify_cert)
        event = MISPEvent()

        event.info = "Observed Malicious IP Activity"
        event.analysis = 2
        event.threat_level_id = 1
        event.distribution = 3
        event.add_tag('tlp:green')

        for ip_data in ips_datas:
            event.add_attribute(type='ip-dst', value=ip_data['Ip address'], comment=f"Ip: {ip_data['Ip address']}\nCountry Code: {ip_data['country Code']}\nInternet service provider: {ip_data['isp']}\nUsage type: {ip_data['usage Type']}\n\nIs white listed: {ip_data['is white listed']}\nAbuse Confidence Score: {ip_data['abuse Confidence Score']}\nIs Tor: {ip_data['is Tor']}\nTotal reports: {ip_data['total Reports']}\nNum Distinct Users: {ip_data['num Distinct Users']}", disable_correlation=False)

        event.published = True
        misp.add_event(event)


class misp_uploader:
    def __init__(self) -> None:
        self.misp_instance = Misp("misp api")

    
    def misp_ips(self):
        ips = Ips(ip_list.serpro_ip_tracker.ip_tracker())
        abuseip = abuseipdb.abuseip_api("API abuseipdb")
        abuseip = abuseip.search(ips.datas)
        self.misp_instance.misp_event_creator_IPS(abuseip) 
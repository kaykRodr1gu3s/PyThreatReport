import pymisp


import Tools.abuseipdb as abuseipdb
from Tools import serpro_ip


class Misp:
    def __init__(self, misp_API: str):

        self.misp_endpoint = "https://localhost"
        self.misp_api = misp_API
        self.misp_verify_cert = False


    def misp_event_creator(self, ips: list, abuseip: list):
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
        
        for key, ip in enumerate(ips):
            
            ips_infos = abuseip[key]
            event.add_attribute("ip-dst", ip, comment=f"Ip: {ips_infos['Ip address']}\nDomain: {ips_infos['domain']}\nCountry Code: {ips_infos['country Code']}\nInternet service provider: {ips_infos['isp']}\nUsage type: {ips_infos['usage Type']}\n\nis white listed: {ips_infos['is white listed']}\nabuse Confidence Score: {ips_infos['abuse Confidence Score']}\nis tor: {ips_infos['is Tor']}\ntotal reports: {ips_infos['total Reports']}\nnum Distinct Users: {ips_infos['num Distinct Users']}", disable_correlation=False)
            

        event.published = True
        misp.add_event(event)


# The serpro is a code imported  from Tools folder.
ips = serpro_ip.serpro_ip_tracker()
ips = ips.ip_tracker()


# The abuseipdb is a code imported from Tools folder
abuseip = abuseipdb.abuseip_api("your abusedb API")
abuseip_datas = abuseip.search(ips)


#initialing the Misp class with the arguments passed
misp = Misp("Your misp API")
misp.misp_event_creator(ips, abuseip_datas)



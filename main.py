from pymisp import ExpandedPyMISP, MISPEvent

import Tools.analyzer.abuseipdb as abuseipdb
from class_base import Datas
import Tools.Datas.ips as ip_list
from Tools.analyzer.hashes_analyzer import hash_analyse




class Ips(Datas):
    """
    This class will recive the ips and save on the self.datas attribute 
    """
    def __init__(self, datas): 
        self.datas = datas


class Hashes(Datas):
    """
    This class will recive the hash and save on the self.datas attribute
    """
    def __init__(self, datas):
        self.datas = datas


class Misp:
    """
    This class will connect with misp utilizing the library pymisp

    Args >>> misp api

    if your endpoint is different, just need to change the self.misp_endpoint
    
    """
    def __init__(self, misp_API: str):

        self.misp_endpoint = "https://localhost"
        self.misp_api = misp_API
        self.misp_verify_cert = False


    def misp_event_creator_IPS(self, ips_datas: list):
        """
        This function will upload the ips already analyzed by abuseipdb to the MISP using the API.
        
        args >>> list of dict 

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

    
    def misp_event_creator_HASH(self, hash_datas: list):
        """
        This function will upload the ips already analyzed by abuseipdb to the MISP using the API.
        args >>> list of dicts
        """
        
        misp = ExpandedPyMISP(self.misp_endpoint, self.misp_api, self.misp_verify_cert)
        event = MISPEvent()

        event.info = "Malicious MD5 hash"
        event.analysis = 2
        event.threat_level_id = 1
        event.distribution = 3
        event.add_tag('tlp:green')

        for hash_ in hash_datas[0]:
            mitre_datas = ''
            for mitre in hash_datas[0][hash_]['mitre_attcks']:
                mitre_datas += f'\n{mitre}\n'

            event.add_attribute(type='md5', value=hash_ ,comment=f"MD5: {hash_datas[0][hash_]['md5']}\nsha256: {hash_datas[0][hash_]['sha256']}\nsha512:{hash_datas[0][hash_]['sha512']}\n\nTags: {hash_datas[0][hash_]['tags']}\ncrowdstrike_ai: {hash_datas[0][hash_]['crowdstrike_ai']}\nenvironment_description: {hash_datas[0][hash_]['environment_description']}\nType_short: {hash_datas[0][hash_]['type_short']}\nFile size: {hash_datas[0][hash_]['size']}\n\nentrypoint: {hash_datas[0][hash_]['entrypoint']}\nentrypoint_section: {hash_datas[0][hash_]['entrypoint_section']}\ndll_characteristics: {hash_datas[0][hash_]['dll_characteristics']}\nurl_analysis: {hash_datas[0][hash_]['url_analysis']}\nthreat_score: {hash_datas[0][hash_]['threat_score']}\nthreat_level: {hash_datas[0][hash_]['threat_level']}\nverdict: {hash_datas[0][hash_]['verdict']}\n\nmitre_attcks: {mitre_datas}", disable_correlation=False)
        for hash_ in hash_datas[1]:
            event.add_attribute(type='md5', value=hash_ ,comment="Empty", disable_correlation=False)

        event.published = True
        misp.add_event(event)



class misp_uploader:
    """
    This class will instantiate the Misp class
    """
    def __init__(self) -> None:
        self.misp_instance = Misp("MISP API")
    
    def misp_ips(self):
        """
        This method will init the misp_event_creator_HASH method from misp class with the correct arguments
        """
        ips = Ips(ip_list.serpro_ip_tracker.ip_tracker())
        abuseip = abuseipdb.abuseip_api("abuseipdb API")
        abuseip = abuseip.search(ips.datas)
        self.misp_instance.misp_event_creator_IPS(abuseip) 


    def misp_hash(self):
        """
        This method will init the misp_event_creator_HASH method from misp class with the correct arguments
        """
        hashes = hash_analyse("API")
        hashes.search
        hash_list = Hashes(hashes.all_datas)
        self.misp_instance.misp_event_creator_HASH(hash_list.datas)

def misp(obj):
    """
    This function will execute the misp_hash and misp_ip method from the class misp uploader

    Arg >>> misp_uploader() 

    """
    obj.misp_ips()
    obj.misp_hash()

misp_datas= misp(misp_uploader())


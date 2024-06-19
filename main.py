from pymisp import ExpandedPyMISP, MISPEvent
from dotenv import load_dotenv
from os import getenv
from datetime import datetime
import pytz


import Tools.analyzer.abuseipdb as abuseipdb
from Tools.analyzer.hashes_analyzer import hash_analyse
import Tools.Datas.ips as ip_list
import Tools.Datas.hashes as hash_list
from Tools.Database.Database import Ip, Hash 



class consulting_db:
    def __init__(self):
        self.ips = []
        
        self.date = datetime.now(pytz.timezone("America/Sao_Paulo")).strftime("%d/%m/%Y %I:%M %p")
        self.data_ips_to_db = []

    def ip_info(self, datas):

        def consulter():
            ips_in_db = []
            for c in  ips.select_data():
                ips_in_db.append(dict(c)["Ip"])
            return ips_in_db       
             
        ips =  Ip("ips")

        ips_in_db = consulter()

        for ip in datas:
            if ip not in ips_in_db:
                self.ips.append(datas[ip]['ipAddress'])
                self.data_ips_to_db.append((datas[ip]['ipAddress'], datas[ip]['abuseConfidenceScore'], self.date))

        def insert_value():
            ips.inserting_value(self.data_ips_to_db)

        insert_value()



class Misp:
    """
    This class will connect with misp utilizing the library pymisp and report ips and hashes
    """
    def __init__(self, ips_in_db):
        load_dotenv()
        ips_list = abuseipdb.Abuseip_Api()
        hashes = hash_analyse()

        self.misp_endpoint = getenv("misp_endpoint")
        self.misp_api = getenv("misp_api")
        self.misp_verify_cert = False
        self.ips_datas = ips_list.search(ip_list.serpro_ip_tracker.ip_tracker())
        self.hashes_list = hashes.search(hash_list.hashes_function()) 
        self.ips_in_db = ips_in_db


    def misp_event_creator(self):
        """
        This function will create the events on misp
        """
        def ips():
            """
            This function will create the event and add the attribute on misp
            """
            misp = ExpandedPyMISP(self.misp_endpoint, self.misp_api, self.misp_verify_cert)
            event = MISPEvent()

            event.info = "Observed Malicious IP Activity"
            event.analysis = 2
            event.threat_level_id = 1
            event.distribution = 3
            event.add_tag('tlp:green')
            if self.ips_in_db:
                for ip in self.ips_in_db:
                    event.add_attribute(type='ip-dst', value=self.ips_datas[ip]['ipAddress'], comment=f"Ip: {self.ips_datas[ip]['ipAddress']}\nCountry Code: {self.ips_datas[ip]['countryCode']}\nInternet service provider: {self.ips_datas[ip]['isp']}\nUsage type: {self.ips_datas[ip]['usageType']}\n\nIs white listed: {self.ips_datas[ip]['isWhitelisted']}\nAbuse Confidence Score: {self.ips_datas[ip]['abuseConfidenceScore']}\nIs Tor: {self.ips_datas[ip]['isTor']}\nTotal reports: {self.ips_datas[ip]['totalReports']}\nNum Distinct Users: {self.ips_datas[ip]['numDistinctUsers']}", disable_correlation=False)
    
                event.published = True
                misp.add_event(event)
            else:
                print("ta vazio")
        def hashes():
            
            misp = ExpandedPyMISP(self.misp_endpoint, self.misp_api, self.misp_verify_cert)
            event = MISPEvent()

            event.info = "Malicious MD5 hash"
            event.analysis = 2
            event.threat_level_id = 1
            event.distribution = 3
            event.add_tag('tlp:green')

            for hash_ in self.hashes_list[0]:
                mitre_datas = ''
                for mitre in self.hashes_list[0][hash_]['mitre_attcks']:
                    mitre_datas += f'\n{mitre}\n'

                event.add_attribute(type='md5', value=hash_ ,comment=f"MD5: {self.hashes_list[0][hash_]['md5']}\nsha256: {self.hashes_list[0][hash_]['sha256']}\nsha512:{self.hashes_list[0][hash_]['sha512']}\n\nTags: {self.hashes_list[0][hash_]['tags']}\ncrowdstrike_ai: {self.hashes_list[0][hash_]['crowdstrike_ai']}\nenvironment_description: {self.hashes_list[0][hash_]['environment_description']}\nType_short: {self.hashes_list[0][hash_]['type_short']}\nFile size: {self.hashes_list[0][hash_]['size']}\n\nentrypoint: {self.hashes_list[0][hash_]['entrypoint']}\nentrypoint_section: {self.hashes_list[0][hash_]['entrypoint_section']}\ndll_characteristics: {self.hashes_list[0][hash_]['dll_characteristics']}\nurl_analysis: {self.hashes_list[0][hash_]['url_analysis']}\nthreat_score: {self.hashes_list[0][hash_]['threat_score']}\nthreat_level: {self.hashes_list[0][hash_]['threat_level']}\nverdict: {self.hashes_list[0][hash_]['verdict']}\n\nmitre_attcks: {mitre_datas}", disable_correlation=False)
            for hash_ in self.hashes_list[1]:
                event.add_attribute(type='md5', value=hash_ ,comment="Empty", disable_correlation=False)

            event.published = True
            misp.add_event(event)           
        ips()
        hashes()


ips_list = ip_list.serpro_ip_tracker.ip_tracker()
abuseipdb = abuseipdb.Abuseip_Api()
datas_result = abuseipdb.search(ips_list)

db= consulting_db()
db.ip_info(datas_result)

# misp = Misp(a1.ips)
# misp.misp_event_creator()
from pymisp import ExpandedPyMISP, MISPEvent
from dotenv import load_dotenv
from os import getenv
from datetime import datetime
import pytz

import Tools.analyzer.abuseipdb as abuseipdb
import Tools.Datas.ips as ip_list
from Tools.Database.Database import Ips_Db 


class consulting_db:
    def __init__(self):
        self.ips = []
        self.date = datetime.now(pytz.timezone("America/Sao_Paulo")).strftime("%d/%m/%Y %I:%M %p")
        self.data_ips_to_db = []
        self.class_instance = Ips_Db()
 
    def ip_info(self, datas):
        """
        This method will consult your database and verify if have the ip address in your databse.
        """

        def consulter():
            """
            This function will execute a SQL query and return a the ips on the database
            """
            
            ips_in_db = []
            for ip in self.class_instance.select_data():
                ips_in_db.append(dict(ip)["Ip"])
            return ips_in_db       
             
        ips_in_db = consulter()
        
        for ip in datas:
            if ip not in ips_in_db:
                self.ips.append(datas[ip]['ipAddress'])
                self.data_ips_to_db.append((datas[ip]['ipAddress'], datas[ip]['abuseConfidenceScore'], self.date))
                print(f"nao temos o ip {datas[ip]['ipAddress']}")
            else:
                print(f"Temos o ip {ip}")
        def insert_value():
            """
            This method will insert the values in the database
            """
            self.class_instance.inserting_value(self.data_ips_to_db)

        insert_value()
    
        return self.class_instance



class Misp:
    """
    This class will connect with misp utilizing the library pymisp and report ips and hashes
    """
    def __init__(self, ip_result, ips_to_upload):
        load_dotenv()
        self.misp_endpoint = getenv("misp_endpoint")
        self.misp_api = getenv("misp_api")
        self.misp_verify_cert = False
        self.ips_datas = ip_result
        self.ips_in_db = ips_to_upload


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

        ips()


ips_list = ip_list.serpro_ip_tracker.ip_tracker()
abuseipdb = abuseipdb.Abuseip_Api()
datas_result = abuseipdb.search(ips_list)

db = consulting_db()
db.ip_info(datas_result)

misp = Misp(datas_result, db.ips)
misp.misp_event_creator()
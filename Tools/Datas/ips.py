import requests

class serpro_ip_tracker:
    """
    This class will collect all ips on https://s3.i02.estaleiro.serpro.gov.br/blocklist/blocklist.txt
    
    """
    @classmethod
    def ip_tracker(cls) -> list:
        """
        This class will return the ip list for be passed as argument to class Ips on main.py
        """

        list_ip = []
        req = requests.get("https://s3.i02.estaleiro.serpro.gov.br/blocklist/blocklist.txt")

        
        ips_list = req.content.decode("utf-8").split("\n")

        for ip in ips_list:
            list_ip.append(ip)            
            if len(list_ip) == 10:
                return list_ip
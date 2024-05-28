import requests

class serpro_ip_tracker:
    """
    This class will collect all ips on https://s3.i02.estaleiro.serpro.gov.br/blocklist/blocklist.txt
    
    """
    @staticmethod
    def ip_tracker():
        """
        This folder will return a list of ips 
        """

        list_ip = []
        req = requests.get("https://s3.i02.estaleiro.serpro.gov.br/blocklist/blocklist.txt")

        
        ips_list = req.content.decode("utf-8").split("\n")

        for ip in ips_list:
            list_ip.append(ip)            
            if len(list_ip) == 20:
                return list_ip



print(serpro_ip_tracker.ip_tracker())
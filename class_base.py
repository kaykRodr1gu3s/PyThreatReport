from abc import ABC, abstractclassmethod


class analyzer_base(ABC):
    """This abstract class will be inherited by the abuseipdb ant the virustotal API"""
    @abstractclassmethod
    def __init__(self):
        pass

    @abstractclassmethod
    def search(self):
        pass

class Datas(ABC):
    def __init__(self, datas):
        self.datas = datas
        """
        The datas is the ips or hash value
        """




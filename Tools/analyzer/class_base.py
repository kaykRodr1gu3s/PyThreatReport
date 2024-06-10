from abc import abstractclassmethod, ABC


class analyzer_base(ABC):
    """This abstract class will be inherited by the abuseipdb ant the virustotal API"""
    @abstractclassmethod
    def __init__(self):
        pass

    @abstractclassmethod
    def search(self):
        pass

import requests
from os import getenv
from dotenv import load_dotenv

from Tools.analyzer.class_base import analyzer_base

class hash_analyse(analyzer_base):
    """
    This class will analyse the hashes passed on __init__ method
    """
    def __init__(self):
        """
        it Will initialize the class with some attribute 

        Args >>> API from hybrid analysis
        """
        self.endpoint = "https://hybrid-analysis.com/api/v2/search/hash"
        self.header = {f"accept":"application/json", "api-key": getenv("hybrid_analysis_api"), "Content-Type":"application/x-www-form-urlencoded"}
        self.all_datas = []
        self.hash_content = {}
        self.empty_hash_value = {}

    def search(self, hash_list: list) -> list:
        """
        This method will request thought api the hybrid analysis and return a json

        output >>> list
        """
        for hash_ in hash_list:

            def query(func):
                """
                This decorator will request and parse the datas

                Args >>> dict_keys decorator
                """
                req = requests.post(self.endpoint, headers=self.header, data={'hash':hash_}).json()
                if req:
                    dict_datas = {key:req[0][key] for key in func()}
                    self.hash_content[hash_] = dict_datas 

                else:
                    self.empty_hash_value[hash_] = None 

            @query  
            def dict_keys(): 
                datas = ['tags','crowdstrike_ai', 'environment_description', 'size', 'type_short', 'md5', 'sha256', 'sha512', 'entrypoint', 'entrypoint_section', 'dll_characteristics',
                        'url_analysis', 'threat_score', 'threat_level', 'verdict','mitre_attcks']
                return datas
            
        self.all_datas.append(self.hash_content); self.all_datas.append(self.empty_hash_value) 
        return self.all_datas
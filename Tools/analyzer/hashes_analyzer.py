import requests
from class_base import analyzer_base
from Tools.Datas.hashes import hashes_function





class hash_analyse(analyzer_base):
    def __init__(self):

        self.endpoint = "https://hybrid-analysis.com/api/v2/search/hash"
        self.header = {"accept":"application/json", "api-key": "API", "Content-Type":"application/x-www-form-urlencoded"}
        self.hashes = hashes_function()
        self.all_datas = []
        self.hash_content = {}
        self.empty_hash_value = {}

    @property
    def search(self):
        for hash_ in self.hashes:

            def query(func):
    
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
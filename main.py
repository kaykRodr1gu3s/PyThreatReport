import pymisp
import requests


url_block_list = "https://s3.i02.estaleiro.serpro.gov.br/blocklist/blocklist.txt"
url = "https://localhost"
api_key = "apikey"
misp_verify_cert = False

misp = pymisp.ExpandedPyMISP(url, api_key, misp_verify_cert)

event = pymisp.MISPEvent() #trabalhar com evento do misp
event.info = "With API"
event.analysis = "1"
event.threat_level_id = "1"
event.distribution = "0"
event.add_tag('tlp:green')


ip_list = requests.get(url_block_list)

for ips in ip_list:
    ip_list = ips.decode("utf-8").split("\n")
    for ip in ip_list:
        event.add_attribute("ip-dst", str(ip), comment="example", disable_correlation=False)
event.published = True
event = misp.add_event(event)
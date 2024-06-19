import sqlite3
from pathlib import Path
from datetime import datetime
import pytz

class Ips_Db:
    def __init__(self,option: str):
            
            self.conection = sqlite3.connect("ips_hashes.sqlite3")
            self.cursor = self.conection.cursor()
            self.cursor.row_factory = sqlite3.Row
            self.option = option

    @property
    def create_table(self):
        if self.option == "ips":

            try:
                self.cursor.execute("CREATE TABLE Ips_tables(Ip TEXT UNIQUE, Abuse_Confidence_Score TEXT, Date DATE)")
                self.conection.commit()

            except Exception as Table_aready_exist:
                print(Table_aready_exist)

        elif self.option == "hash":
            try:
                self.cursor.execute("CREATE TABLE Hash_table(Hash TEXT UNIQUE, Veredict TEXT, Date DATE)")
                print("tabela criada")
                self.conection.commit()
            except Exception as Table_aready_exist:
                print(Table_aready_exist)

    def inserting_value(self, data: list[tuple]):
        if self.option == "ips":
            self.cursor.executemany("INSERT INTO Ips_tables(Ip, Abuse_Confidence_Score, Date) VALUES (?,?,?)", data)
            self.conection.commit()      
        else:
            self.cursor.executemany("INSERT INTO Hash_table(Ip, Abuse_Confidence_Score, Date) VALUES (?,?,?)", data)
            self.conection.commit()      

    def select_data(self):
        if self.option == "ips":
           return self.cursor.execute("SELECT Ip FROM Ips_tables").fetchall()
        else:
            return self.cursor.execute("SELECT Ip FROM Ips_tables").fetchall()
    

class Ip(Ips_Db):
    pass

class Hash(Ips_Db):
    pass

ip = Ip("ips")
hashes = Hash("hash")

ip.create_table
hashes.create_table
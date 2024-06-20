import sqlite3
from pathlib import Path

class Ips_Db:
    def __init__(self):
            ROOT_PATH = Path(__file__).parent
            self.conection = sqlite3.connect(ROOT_PATH / "ips.sqlite3")
            self.cursor = self.conection.cursor()
            self.cursor.row_factory = sqlite3.Row

    @property
    def create_table(self):
        """
        This method will create the database
        """
        try:
            self.cursor.execute("CREATE TABLE Ips_tables(Ip TEXT UNIQUE, Abuse_Confidence_Score TEXT, Date DATE)")
            self.conection.commit()

        except Exception as Table_aready_exist:
            print(Table_aready_exist)

    def inserting_value(self, data: list[tuple]):
        """
        This method will insert the data to the database
        """
        self.cursor.executemany("INSERT INTO Ips_tables(Ip, Abuse_Confidence_Score, Date) VALUES (?,?,?)", data)
        self.conection.commit()            

    def select_data(self):
        """
        This method will return all ip from the databse
        """
        return self.cursor.execute("SELECT Ip FROM Ips_tables").fetchall()
    
ip = Ips_Db()
ip.create_table
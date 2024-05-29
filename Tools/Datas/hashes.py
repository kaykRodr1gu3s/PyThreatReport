class Hashes:
    def __init__(self, file):
        self.file = open(file)

    def __iter__(self):
        return self
    
    def __next__(self):
    
        try:
            line = self.file.readline()

            return line


        except:
            raise StopIteration
        

def hashes():

    hash_list = []
    for line in Hashes("Tools\\Datas\\hashes.txt"):
        if len(hash_list) == 500:
            return hash_list
            
        else:
            hash_list.append(line.replace("\n", ""))
        


print(hashes())
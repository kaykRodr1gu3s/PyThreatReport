class Hashes_class:
    """This class will iterate to full-hash-md5-aa.txt file, and return a list of file.
    """

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
        
def hashes_function():
    """
    This function will return the quantity selected of ips
    """
    hash_list = []
    for line in Hashes_class("Tools\\Datas\\full-hash-md5-aa.txt"):
        if len(hash_list) == 25:
            return hash_list
            
        else:
            hash_list.append(line.replace("\n", ""))

        

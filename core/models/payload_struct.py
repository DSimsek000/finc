class Payload:

    def __init__(self, file, rce=False, successWords=None, successRegex=None):
        self.file = file
        self.rce = rce
        self.successWords = successWords
        self.successRegex = successRegex

class InputRequest:

    def __init__(self):
        self.host = ""
        # contains scheme+domain+path+script
        self.url_script_path = ""
        self.method = "GET"

        self.cookies = {}
        self.extra_headers = {}
        self.data = {}
        self.json = {}
        self.params = {}

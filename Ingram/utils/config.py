"""global configure arguments"""
class Config:

    def __init__(self):
        # the defaultdict doesn't report an error when you give a 
        # nonexistent idx, which is difficult to trace errors during
        # debugging, so we use python built-in dict.
        self.config_dict = {}

    def set_val(self, key, val):
        self.config_dict[key] = val

    def get_val(self, key):
        return self.config_dict[key]

    def __getitem__(self, key):
        return self.config_dict[key]


global config
config = Config()
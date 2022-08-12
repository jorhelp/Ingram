"""global configure arguments"""
import collections


class Config:
    def __init__(self):
        self.config_dict = collections.defaultdict(lambda: None)

    def set_val(self, key, val):
        self.config_dict[key] = val

    def get_val(self, key):
        return self.config_dict[key]

    def __getitem__(self, key):
        return self.config_dict[key]


global config
config = Config()
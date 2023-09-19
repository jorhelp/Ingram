import importlib
import os
from collections import defaultdict

from .base import POCTemplate


for file in os.listdir(os.path.dirname(__file__)):
    if (file_name := file.split('.')[0]) not in ['__init__', 'base']:
        importlib.import_module(f".{file_name}", 'Ingram.pocs')


def get_poc_dict(config):
    poc_dict = defaultdict(list)
    for POC in POCTemplate.poc_classes:
        poc = POC(config)
        poc_dict[poc.product].append(poc)
    return poc_dict
import platform


def os_check() -> str:
    """check the operate system"""
    _os = platform.system().lower()
    if _os == 'windows': return 'windows'
    elif _os == 'linux': return 'linux'
    else: return 'other'


def singleton(cls, *args, **kwargs):
    """singleton decorator"""
    instance = {}
    def wrapper(*args, **kwargs):
        if cls not in instance:
            instance[cls] = cls(*args, **kwargs)
        return instance[cls]
    return wrapper
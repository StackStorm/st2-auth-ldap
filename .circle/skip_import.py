import __builtin__

def mock(name, g, l, fromlist, *args):
    if not fromlist:
        fromlist = []

    mod = {
        '__all__': fromlist
    }

    for var in fromlist:
        mod[var] = None

    return type(name, (object,), mod)

__builtin__.__import__ = mock

import string
from itertools import chain, product
from random import shuffle




def combinations(minlength, maxlength):
    print("Generating combinations")
    charset = string.digits # string.ascii_letters + string.punctuation + string.digits
    lengths = list(range(minlength, maxlength+1))
    cands = [''.join(candidate)
            for candidate in chain.from_iterable(product(charset, repeat=i)
            for i in lengths)]
    shuffle(cands)
    print(f"Possible combinations: {len(cands)}")
    return cands

combinations(8, 8)


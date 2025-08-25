# progressbar.py

SPACE = 34
DISABLE_PROGRESS_BAR = False

def progress_bar(iteration, total, prefix='', suffix='', decimals=2, length=50, fill='█', unfill='-', print_end="\r"):
    r"""
    Call this function in a loop to create terminal progress bar
    
    :param iteration: Current iteration (Int)
    :param total: Total iterations (Int)
    :param prefix: Prefix string (Str)
    :param suffix: Suffix string (Str)
    :param decimals: Positive number of decimals in percent complete (Int)
    :param length: Character length of bar (Int)
    :param fill: Bar fill character (Str)
    :param unfill: Bar empty character (Str)
    :param print_end: End character (e.g. "\r", "\r\n") (Str)
    """
    if not DISABLE_PROGRESS_BAR:
        percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
        filled_length = int(length * iteration // total)
        bar = fill * filled_length + unfill * (length - filled_length)
        print(f'\r{prefix} |{bar}| {percent}% {suffix}', end=print_end)

        # Print new line on complete
        if iteration >= total:
            print()
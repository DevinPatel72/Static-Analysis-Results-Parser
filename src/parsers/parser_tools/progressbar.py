# progressbar.py

SPACE = 34
DISABLE_PROGRESS_BAR = False
last_percent = -1

def progress_bar(scanner, iteration, total, prefix='', suffix='', decimals=2, length=50, fill='█', unfill='-', print_end="\r"):
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
    import parsers
    if not DISABLE_PROGRESS_BAR:
        # GUI loading screen
        if parsers.GUI_MODE and parsers.loader is not None:
            if parsers.loader.cancelled():
                return True
            percent = int(100 * iteration / float(total))
            if percent - last_percent >= 1:
                last_percent = percent
                status = 'Complete' if iteration >= total else 'Parsing'
                parsers.loader.queue_scanner_update(scanner, percent, status)
        
        # Terminal loading screen
        else:
            percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
            filled_length = int(length * iteration // total)
            bar = fill * filled_length + unfill * (length - filled_length)
            print(f'\r{prefix} |{bar}| {percent}% {suffix}', end=print_end)

            # Print new line on complete
            if iteration >= total:
                print()
    return False
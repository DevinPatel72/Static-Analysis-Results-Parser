# progressbar.py

import parsers

SPACE = 34
DISABLE_PROGRESS_BAR = False

# Store modulo and old total to speed up execution
_modulo = -1
_old_total = -1

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
    :param scanner: Scanner representing the progress bar
    """
    global _modulo, _old_total
    
    # Zero check
    if total == 0:
        total = 1
    
    # Iteration check at every 47th division of the total amount
    if total != _old_total:
        _modulo = (total // 47) if (total // 47) > 0 else 1
        _old_total = total

    if iteration < total and iteration % _modulo != 0:
        return
    
    # If GUI mode, send message to loading screen
    if parsers.GUI_MODE:
        parsers.progress_queue.put({
            "type": "progress",
            "status": prefix.strip(),
            "percent": (iteration / total) * 100
        })
    # If CLI mode, print if progress bar is not disabled
    elif not DISABLE_PROGRESS_BAR:
        percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
        filled_length = int(length * iteration // total)
        bar = fill * filled_length + unfill * (length - filled_length)
        print(f'\r{prefix} |{bar}| {percent}% {suffix}', end=print_end)

        # Print new line on complete
        if iteration >= total:
            print()
# parser_logger.py

import inspect
import logging
import logging.handlers
import multiprocessing

import parsers
from tkinter import messagebox

_logger = logging.getLogger(parsers.PROG_NAME_ABBR)
_logger.propagate = False
_listener = None
_queue = None

_initialized = False


def initialize(
    *,
    level=logging.INFO,
    handlers=None
):
    """
    Initialize the logger in the current process.
    Safe to call multiple times.
    """
    global _initialized

    if _initialized:
        return

    _logger.setLevel(level)

    if handlers is not None:
        for handler in handlers:
            _logger.addHandler(handler)

    _initialized = True


def initialize_main(logfile):
    """
    Configure logging for the main process.
    """

    file = logging.FileHandler(logfile, encoding="utf-8", mode='w')
    formatter = logging.Formatter(fmt='%(name)-18s :: %(levelname)-8s :: %(message)s')
    file.setFormatter(formatter)
    
    consoleHandler = logging.StreamHandler()
    consoleHandler.setLevel(logging.CRITICAL)
    consoleHandler.setFormatter(logging.Formatter(fmt='\n[%(levelname)s]  %(message)s'))

    initialize(handlers=[file, consoleHandler])


def initialize_worker(queue):
    global _initialized

    _initialized = False

    for h in list(_logger.handlers):
        _logger.removeHandler(h)
        h.close()

    initialize(
        handlers=[logging.handlers.QueueHandler(queue)]
    )

def initialize_multiprocessing():
    global _listener, _queue

    if _queue is None:
        _queue = multiprocessing.Queue()

    if _listener is None:
        _listener = logging.handlers.QueueListener(
            _queue,
            *_logger.handlers
        )
        _listener.start()
    
    return _queue

def get_logger(name=None):
    if name is None:
        return _logger
    else:
        return _logger.getChild(name)

def _caller_logger():
    frame = inspect.currentframe().f_back.f_back
    module = inspect.getmodule(frame)
    name = module.__name__ if module else parsers.PROG_NAME_ABBR
    return _logger.getChild(name)

def info(msg, *args, **kwargs):
    _caller_logger().info(msg, *args, **kwargs)

def warning(msg, *args, **kwargs):
    _caller_logger().warning(msg, *args, **kwargs)

def error(msg, *args, **kwargs):
    _caller_logger().error(msg, *args, **kwargs)

def critical(msg, *args, **kwargs):
    _caller_logger().critical(msg, *args, **kwargs)

def debug(msg, *args, **kwargs):
    _caller_logger().debug(msg, *args, **kwargs)


def message_box(title, msg, level):
    if level == 'error':
        messagebox.showerror(title, msg)
    elif level == 'warning':
        messagebox.showwarning(title, msg)
    elif level == 'info':
        messagebox.showinfo(title, msg)

def console(msg, title='', level='info', *, no_console=False, no_logging=False):
    if not no_logging:
        logger = _caller_logger()
        
        if level == 'critical':
            logger.critical(msg)
        elif level == 'error':
            logger.error(msg)
        elif level == 'warning':
            logger.warning(msg)
        elif level == 'info':
            logger.info(msg)
        elif level == 'debug':
            logger.debug(msg)
    
    # Once logged, report it
    if not no_console:
        if parsers.GUI_MODE:
            message_box(title, msg, level)
        elif level == 'critical':
            print(f"[CRITICAL]  {msg}")
        else:
            print(f'[{level.upper()}]  {msg}')

def close_logger():
    global _listener

    if _listener is not None:
        _listener.stop()
        _listener = None
    
    logging.shutdown()

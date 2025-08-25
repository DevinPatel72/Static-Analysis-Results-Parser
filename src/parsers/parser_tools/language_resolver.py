# language_resolver.py

def resolve_lang(lang):
    if lang in ['.cpp', '.c', '.cc', '.h', '.hh', '.hpp']:
        return 'c/c++'
    elif lang in ['cs']:
        return 'c#'
    elif lang in ['.cl']:
        return 'API'
    elif lang == '.pl':
        return 'perl'
    elif lang == '.py':
        return 'python'
    elif lang == '.vbs':
        return 'vbs'
    elif lang == '.js':
        return 'javascript'
    elif lang == '.html':
        return 'html'
    elif lang in ['.adb', '.ads', '.ada']:
        return 'ada'
    else:
        return ''